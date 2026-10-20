"""Label-free serving CLI for the frozen eight-class experimental pipeline."""
from pathlib import Path
import argparse,json,hashlib
import numpy as np
import pandas as pd
import joblib
from core import rvfl_class
from train import daily,chosen
from review_policy import feature_table,rank_hosts
from observed_contract import check_observed_contract

def predict(features,metadata,output,max_reviews=20,as_of=None):
    if max_reviews<1:raise ValueError('Review budget must be positive')
    root=Path(__file__).resolve().parent
    frozen=json.loads((root/'run/frozen.json').read_text())
    modelpath=root/'run/pipeline.joblib'
    if hashlib.sha256(modelpath.read_bytes()).hexdigest()!=frozen['model_sha256']:raise ValueError('Frozen model hash mismatch')
    rvfl_class();bundle=joblib.load(modelpath)
    X=pd.read_csv(features);raw=pd.read_csv(metadata)
    source_admission=check_observed_contract(raw)
    required=['hostname','date']
    if not set(required)<=set(raw):raise ValueError('hostname and date metadata required')
    M=raw[required].copy()  # Explicit allowlist: no labels or campaign/permission flags.
    if not len(X) or len(X)!=len(M) or list(X)!=bundle['domain'].columns:raise ValueError('Empty/unaligned inputs or wrong 40-column order')
    a=X.to_numpy(float)
    if not np.isfinite(a).all() or (a<0).any():raise ValueError('Nonfinite or negative behavior values')
    if M.hostname.isna().any() or M.duplicated(required).any():raise ValueError('Missing host or duplicate host/day')
    dates=pd.to_datetime(M.date,format='%Y-%m-%d',errors='raise')
    if (dates.dt.normalize()!=dates).any():raise ValueError('Day-wise date metadata required')
    for c in ['after_hours_logon_ratio','after_hours_usb_ratio','external_domain_ratio']:
        if not X[c].between(0,1).all():raise ValueError('Invalid ratio/flag: '+c)
    if not X.weekend_activity.isin([0,1]).all():raise ValueError('weekend_activity must be binary')
    for sub,total in [('unique_pc_count','successful_logons'),('new_filename_count','unique_filename_count'),
        ('unique_filename_count','file_access_count'),('file_delete_count','file_access_count'),
        ('new_domain_count','unique_domain_count'),('unique_domain_count','http_request_count'),
        ('file_sharing_visit_count','http_request_count'),('unique_remote_ip_count','external_connection_count')]:
        if X[sub].gt(X[total]+1e-7).any():raise ValueError('Invalid subset: '+sub)
    if X.interactive_duration_seconds.gt(86400).any():raise ValueError('Daily duration over 86400 seconds')
    d,F,p=daily(bundle,X,M)
    behavior_path=root/'run/behavior_heads.joblib'
    if behavior_path.exists():
        behavior=joblib.load(behavior_path)
        behavior_freeze=json.loads((root/'run/behavior_frozen.json').read_text())
        if hashlib.sha256(behavior_path.read_bytes()).hexdigest()!=behavior_freeze['sha256']:raise ValueError('Behavior-head hash mismatch')
        if behavior['base_model_sha256']!=frozen['model_sha256']:raise ValueError('Behavior heads use another upstream model')
        for name,head,cutoff in zip(behavior['behaviors'],behavior['heads'],behavior['thresholds']):
            bp=head.predict_proba(F)[:,1]
            d['behavior_probability_'+name]=bp
            d['behavior_label_'+name]=(bp>=cutoff) if cutoff is not None else False
            d['behavior_status_'+name]='calibrated_threshold_applied' if cutoff is not None else 'abstain_calibration_unmet'
    # Fail closed for review coverage if completeness is not supplied.
    # This flag controls eligibility only; it is never an estimator input.
    d['observation_complete']=raw.observation_complete.to_numpy() if 'observation_complete' in raw else 0
    r=rank_hosts(feature_table(d,as_of=as_of),'pair_threat')
    end=pd.to_datetime(r.as_of.iloc[0]);start=end-pd.Timedelta(days=14)
    w=d[pd.to_datetime(d.date).between(start,end)]
    r['novelty_score']=r.hostname.map(w.groupby('hostname').second_domain_anomaly.max())
    r['novelty_evidence_date']=r.hostname.map(w.loc[w.groupby('hostname').second_domain_anomaly.idxmax()].set_index('hostname').date)
    r,q=chosen(r,frozen['review_policy'],max_reviews)
    output=Path(output);output.mkdir(parents=True,exist_ok=True)
    d.to_csv(output/'daily_predictions.csv',index=False);r.to_csv(output/'host_rankings.csv',index=False);q.to_csv(output/'review_queue.csv',index=False)
    summary=dict(model_name='Model V3',classes=bundle['classes'],reviewed=len(q),eligible_hosts=int(r.eligible.sum()),total_hosts=len(r),
        max_reviews=max_reviews,novelty_enabled=frozen['novelty_enabled'],insider_confirmation='not_assessed',
        as_of=str(end.date()),as_of_source='explicit' if as_of is not None else 'latest_input_date',
        coverage_verified='observation_complete' in raw,
        source_admission=source_admission,
        note='No truth labels required. Missing completeness metadata abstains from review. Classifier scenarios are hypotheses; anomaly-only referrals do not confirm a class. pair evidence_dates describe the supervised route; novelty_evidence_date describes anomaly support.')
    reference=root/'run/monitor_reference.json'
    if reference.exists():
        ref=json.loads(reference.read_text());drift=[]
        for name,stats in ref['features'].items():
            edges=np.asarray(stats['edges']);counts=np.histogram(X[name],bins=np.r_[-np.inf,edges,np.inf])[0]
            observed=(counts+1e-6)/(counts.sum()+1e-6*len(counts));expected=np.asarray(stats['fractions'])
            psi=float(np.sum((observed-expected)*np.log(observed/expected)))
            drift.append(dict(feature=name,population_stability_index=psi,observed_rows=len(X)))
        pd.DataFrame(drift).to_csv(output/'feature_shift_monitor.csv',index=False)
        summary['monitor_note']='Univariate shift statistics against synthetic training distribution; descriptive, not validated real-world alarm thresholds.'
    (output/'summary.json').write_text(json.dumps(summary,indent=2),encoding='utf8')
    return summary

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--features',required=True);parser.add_argument('--metadata',required=True)
    parser.add_argument('--output',required=True);parser.add_argument('--max-reviews',type=int,default=20);parser.add_argument('--as-of')
    args=parser.parse_args()
    if args.max_reviews<1:parser.error('--max-reviews must be positive')
    print(json.dumps(predict(args.features,args.metadata,args.output,args.max_reviews,args.as_of),indent=2))
