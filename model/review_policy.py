"""Label-free host ranking and precision-first abstention after frozen V2.

Scores are evidence statistics, not calibrated insider probabilities.
Only the five named inference columns and coverage flags can affect ranking.
"""
import json
import numpy as np
import pandas as pd

METHODS=['v2_error','second_error','pair_error','pair_threat','pair_agreement',
         'top3_error','persistent_error_mix','agreement_peak_pair']
REQUIRED=['hostname','date','drift_error','threat_probability','if_risk']

def feature_table(daily,as_of=None):
    missing=set(REQUIRED)-set(daily)
    if missing:raise ValueError('Missing required inference columns: '+str(sorted(missing)))
    allowed=REQUIRED+(['observation_complete'] if 'observation_complete' in daily else [])
    d=daily[allowed].copy()
    if d.hostname.isna().any():raise ValueError('Missing hostname')
    d['date']=pd.to_datetime(d.date,format='%Y-%m-%d',errors='raise')
    if (d.date.dt.normalize()!=d.date).any():raise ValueError('Metadata must be day-wise')
    if d.duplicated(['hostname','date']).any():raise ValueError('Duplicate host/date keys')
    if not len(d):raise ValueError('No daily observations')
    end=pd.Timestamp(as_of) if as_of is not None else d.date.max()
    end=end.normalize();start=end-pd.Timedelta(days=14)
    needed=pd.date_range(start,end,freq='D')
    rows=[]
    for host,g in d.groupby('hostname',sort=True):
        w=g.loc[g.date.between(start,end)].sort_values('date')
        row=dict(hostname=host,as_of=end.strftime('%Y-%m-%d'),window_start=start.strftime('%Y-%m-%d'),
                 window_end=end.strftime('%Y-%m-%d'),observed_days=len(w),eligible=False,
                 coverage_status='insufficient_contiguous_history')
        for method in METHODS:row[method]=np.nan
        row['evidence_dates']='[]'
        if len(w)!=15 or not np.array_equal(w.date.to_numpy(),needed.to_numpy()):
            rows.append(row);continue
        e=w.drift_error.to_numpy(float);p=w.threat_probability.to_numpy(float);risk=w.if_risk.to_numpy(float)
        if not np.isfinite(np.column_stack([e,p,risk])).all():
            row['coverage_status']='forecast_or_input_unavailable';rows.append(row);continue
        if ((e<0)|(e>1)|(p<0)|(p>1)|(risk<0)|(risk>1)).any():raise ValueError('Scores outside [0,1]')
        if 'observation_complete' in w and not w.observation_complete.eq(1).all():
            row['coverage_status']='incomplete_observation';rows.append(row);continue
        agreement=np.sqrt(e*p)
        epair=np.minimum(e[:-1],e[1:]);ppair=np.minimum(p[:-1],p[1:])
        apair=np.minimum(agreement[:-1],agreement[1:])
        sorted_e=np.sort(e)
        row.update(eligible=True,coverage_status='complete_15_target_days',
            v2_error=float(e.max()*e.mean()*np.sqrt(15)),second_error=float(sorted_e[-2]),
            pair_error=float(epair.max()),pair_threat=float(ppair.max()),pair_agreement=float(apair.max()),
            top3_error=float(sorted_e[-3:].mean()),
            persistent_error_mix=float(.5*epair.max()+.5*sorted_e[-3:].mean()),
            agreement_peak_pair=float(np.sqrt(agreement.max()*apair.max())),
            peak_temporal_error=float(e.max()),mean_temporal_error=float(e.mean()),
            pair_error_index=int(epair.argmax()),pair_threat_index=int(ppair.argmax()),pair_agreement_index=int(apair.argmax()),
            _dates=json.dumps(w.date.dt.strftime('%Y-%m-%d').tolist()),
            _error=json.dumps(e.tolist()),_threat=json.dumps(p.tolist()))
        rows.append(row)
    return pd.DataFrame(rows)

def evidence(row,method):
    if not row.eligible:return '[]'
    dates=json.loads(row._dates);e=np.array(json.loads(row._error));p=np.array(json.loads(row._threat))
    if method in ['pair_error','persistent_error_mix']:i=int(row.pair_error_index);idx=[i,i+1]
    elif method=='pair_threat':i=int(row.pair_threat_index);idx=[i,i+1]
    elif method in ['pair_agreement','agreement_peak_pair']:
        i=int(row.pair_agreement_index);idx=[i,i+1]
        if method=='agreement_peak_pair':idx=sorted(set(idx+[int(np.argmax(np.sqrt(e*p)))]))
    elif method=='second_error':idx=sorted(np.argsort(e)[-2:].tolist())
    elif method=='top3_error':idx=sorted(np.argsort(e)[-3:].tolist())
    else:idx=[int(np.argmax(e))]
    return json.dumps([dict(date=dates[i],temporal_error=float(e[i]),threat_score=float(p[i])) for i in idx])

def rank_hosts(features,method):
    if method not in METHODS:raise ValueError('Unknown ranking method')
    r=features.copy();r['evidence_score']=r[method]
    r=r.sort_values(['eligible','evidence_score','hostname'],ascending=[False,False,True],na_position='last').reset_index(drop=True)
    r.insert(0,'rank',np.arange(1,len(r)+1))
    # Series attribute names beginning '_' are not namedtuple-safe; use iterrows.
    r['evidence_dates']=[evidence(row,method) for _,row in r.iterrows()]
    return r.drop(columns=[c for c in r if c.startswith('_')])

def select_queue(ranked,config,max_reviews=20):
    if max_reviews<1:raise ValueError('max_reviews must be positive')
    result=ranked.copy()
    threshold=config['acceptance_threshold']
    accepted=result.eligible&result.evidence_score.notna()
    if not config['enabled'] or threshold is None:accepted[:]=False
    else:accepted &= result.evidence_score>=threshold
    result['selection_status']=np.where(~result.eligible,'abstain_incomplete_history',
        np.where(accepted,'eligible_for_review','abstain_below_evidence_threshold'))
    if not config['enabled']:result.loc[result.eligible,'selection_status']='abstain_calibration_target_unmet'
    queue=result.loc[accepted].head(max_reviews).copy()
    queue['selection_status']='review_candidate'
    queue['insider_confirmation']='not_assessed'
    queue['ranking_method']=config['ranking_method']
    queue['selection_reason']='Meets frozen evidence threshold; supporting dates attached; confirmation requires investigation.'
    result.loc[result.hostname.isin(queue.hostname),'selection_status']='review_candidate'
    excluded=accepted&~result.hostname.isin(queue.hostname)
    result.loc[excluded,'selection_status']='deferred_review_budget'
    return result,queue
