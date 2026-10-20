"""Eight-class experiment; fresh training/calibration; freeze before final generation."""
import os
os.environ.setdefault('OMP_NUM_THREADS','2')
from pathlib import Path
import sys,json,hashlib,time,importlib.util
sys.stdout.reconfigure(encoding='utf-8')
from datetime import datetime,timezone
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import average_precision_score,classification_report,confusion_matrix,balanced_accuracy_score
from core import DomainStage,CLASSES,fit_booster,windows,rvfl_class,score,host_rank
from review_policy import feature_table,rank_hosts

ROOT=Path(__file__).resolve().parent;WORK=ROOT.parent;OUT=ROOT/'run';OUT.mkdir(exist_ok=True)
def v2_path():
    path=WORK/'architecture_pipeline_v2/run/pipeline.joblib'
    return path if path.exists() else ROOT/'reference_models/v2.joblib'
def prior_policy_path():
    path=WORK/'precision_first_v3/run/frozen_policy.json'
    return path if path.exists() else ROOT/'reference_models/precision_policy.json'
SPEC=dict(name='eight_class_level_d3_cap5',rep='level',depth=3,trees=240,child=40,weight_cap=5)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(name,data):(OUT/name).write_text(json.dumps(data,indent=2,allow_nan=False,default=str),encoding='utf8')
def log(event,**data):
    row=dict(time=datetime.now(timezone.utc).isoformat(),event=event,**data)
    with (OUT/'decisions.jsonl').open('a',encoding='utf8') as f:f.write(json.dumps(row,default=str)+'\n')
    print(event,json.dumps(data,default=str)[:700],flush=True)

def cohort(seed,role,stress=False):
    path=ROOT/'cohorts'/f'{role}_{seed}'
    if not path.exists():
        source=ROOT/('stress_generator.py' if stress else 'cohort_generator.py')
        spec=importlib.util.spec_from_file_location(f'gen{seed}',source);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        module.build(path,seed,False)
    p=path/'development_90_days/daily_features';X=pd.read_csv(p/'X.csv');M=pd.read_csv(p/'metadata.csv')
    M.hostname=f'{role.upper()}{seed}-'+M.hostname;M.agent_id='AGENT-'+M.hostname
    M.campaign_id=M.campaign_id.fillna('').map(lambda c:f'{role}{seed}-'+c if c else '')
    M['split']=role;M['cohort_seed']=seed
    export=ROOT/'data'/f'{role}_{seed}';export.mkdir(parents=True,exist_ok=True)
    X.to_csv(export/'X.csv',index=False,float_format='%.10g');M.to_csv(export/'metadata.csv',index=False)
    log('cohort_ready',seed=seed,role=role,rows=len(M),counts=M.scenario_label.value_counts().to_dict())
    return X,M

def daily(bundle,X,M):
    F,risk,probs,fused,pred,error=score(bundle,X,M[['hostname','date']])
    d=M[['hostname','date']].reset_index(drop=True).copy()
    d['if_risk']=risk;d['threat_probability']=1-probs[:,0];d['fused_risk']=fused
    d['forecasted_risk']=pred;d['drift_error']=error
    # Independent single-day evidence: at least two anomalous domains.
    domaincols=['if_identity','if_device_file','if_web_network','if_execution']
    d['second_domain_anomaly']=np.sort(F[domaincols].to_numpy(),axis=1)[:,-2]
    for i,c in enumerate(bundle['classes']):d['prob_'+c]=probs[:,i]
    d['predicted_scenario']=np.asarray(bundle['classes'])[probs.argmax(axis=1)]
    return d,F,probs

def host_table(d,M):
    r=rank_hosts(feature_table(d),'pair_threat')
    end=pd.to_datetime(r.as_of.iloc[0]);start=end-pd.Timedelta(days=14)
    w=d.loc[pd.to_datetime(d.date).between(start,end)]
    anomaly=w.groupby('hostname').second_domain_anomaly.max()
    r['novelty_score']=r.hostname.map(anomaly)
    mw=M.loc[pd.to_datetime(M.date).between(start,end)]
    truth=mw.groupby('hostname').binary_label.max()
    families=mw.groupby('hostname').scenario_label.agg(lambda s:'|'.join(sorted(set(s)-{'BENIGN'})))
    return r,pd.DataFrame(dict(hostname=r.hostname,binary_label=r.hostname.map(truth),attack_families=r.hostname.map(families)))

def chosen(r,policy,k=20):
    if k<1:raise ValueError('Review budget must be positive')
    primary=r.eligible&(r.pair_threat>=policy['supervised_cutoff']) if policy['supervised_cutoff'] is not None else pd.Series(False,index=r.index)
    novelty=r.eligible&(r.novelty_score>=policy['novelty_cutoff']) if policy['novelty_cutoff'] is not None else pd.Series(False,index=r.index)
    out=r.copy();out['review_route']=np.select([primary,novelty],['supervised_persistence','anomaly_without_class_confirmation'],default='below_cutoff')
    out['route_order']=np.select([primary,novelty],[0,1],default=2)
    out['route_score']=np.where(primary,out.pair_threat,out.novelty_score)
    out=out.sort_values(['route_order','route_score','hostname'],ascending=[True,False,True])
    queue=out.loc[primary.reindex(out.index)|novelty.reindex(out.index)].head(k).copy()
    queue['insider_confirmation']='not_assessed'
    return out,queue

def metric(r,queue,y):
    a=r.merge(y,on='hostname',validate='one_to_one');actual=a.binary_label.eq(1);pred=a.hostname.isin(queue.hostname)
    tp=int((actual&pred).sum());fp=int((~actual&pred).sum());fn=int((actual&~pred).sum());tn=int((~actual&~pred).sum())
    return dict(reviewed=tp+fp,tp=tp,fp=fp,fn=fn,tn=tn,precision=tp/(tp+fp) if tp+fp else None,
        recall=tp/(tp+fn),normal_review_rate=fp/(fp+tn),balanced_accuracy=.5*(tp/(tp+fn)+tn/(fp+tn)))

def binary(y,s,t):
    ok=np.isfinite(s);y=np.asarray(y)[ok];s=np.asarray(s)[ok];p=s>=t
    tp=int(((y==1)&p).sum());fp=int(((y==0)&p).sum());fn=int(((y==1)&~p).sum());tn=int(((y==0)&~p).sum())
    return dict(rows=len(y),tp=tp,fp=fp,fn=fn,tn=tn,precision=tp/(tp+fp) if tp+fp else None,recall=tp/(tp+fn),
        accuracy=(tp+tn)/len(y),balanced_accuracy=.5*(tp/(tp+fn)+tn/(fp+tn)),normal_fpr=fp/(fp+tn),ap=float(average_precision_score(y,s)))

def daily_cutoff(groups,column):
    values=np.concatenate([d[column].dropna().to_numpy() for d,m in groups]);candidates=np.unique(np.r_[np.quantile(values,np.linspace(0,1,251)),1.000001])
    best=None
    for t in candidates:
        ms=[binary(m.binary_label,d[column].to_numpy(),t) for d,m in groups]
        if any(m['normal_fpr']>.03 for m in ms):continue
        key=(min(m['balanced_accuracy'] for m in ms),np.mean([m['balanced_accuracy'] for m in ms]),t)
        if best is None or key>best[0]:best=key,t
    return float(best[1])

def calibrate(frames):
    def summarize(policy):
        ms=[metric(r,chosen(r,policy)[1],y) for r,y in frames]
        tp=sum(m['tp'] for m in ms);fp=sum(m['fp'] for m in ms);fn=sum(m['fn'] for m in ms)
        return dict(policy=policy,tp=tp,fp=fp,precision=tp/(tp+fp) if tp+fp else 0.,recall=tp/(tp+fn),cohorts=ms)
    def legal(v):
        return v['precision']>=.8 and v['recall']>=.5 and v['tp']+v['fp']>=15 and all(m['precision'] is not None and m['precision']>=.7 and m['recall']>=.4 for m in v['cohorts'])
    vals=np.unique(np.concatenate([r.pair_threat.to_numpy() for r,y in frames]));tested=[]
    for t in vals:tested.append(summarize(dict(supervised_cutoff=float(t),novelty_cutoff=None)))
    feasible=[v for v in tested if legal(v)]
    selected=max(feasible,key=lambda v:(v['recall'],v['precision'],v['policy']['supervised_cutoff'])) if feasible else summarize(dict(supervised_cutoff=None,novelty_cutoff=None))
    base=selected;novelties=[]
    if feasible:
        for t in np.unique(np.concatenate([r.novelty_score.to_numpy() for r,y in frames])):
            cand=summarize(dict(supervised_cutoff=base['policy']['supervised_cutoff'],novelty_cutoff=float(t)))
            cand['passes_gate']=legal(cand) and cand['tp']>base['tp'] and all(m['normal_review_rate']<=.02 for m in cand['cohorts'])
            novelties.append(cand)
        passed=[v for v in novelties if v['passes_gate']]
        if passed:selected=max(passed,key=lambda v:(v['recall'],v['precision'],v['policy']['novelty_cutoff']))
    save('calibration_search.json',dict(supervised=tested,novelty=novelties))
    return selected,base

def main():
    begin=time.time()
    if (OUT/'frozen.json').exists():raise RuntimeError('Refuse to overwrite frozen experiment')
    protocol=dict(model_name='Model V3 robustness candidate',classes=CLASSES,spec=SPEC,training_seeds=[66001,66002,66041,66042],calibration_seeds=[66611,66612,66613,66614],
        clustered_training_seeds=[66041,66042],clustered_calibration_seeds=[66613,66614],
        final_standard_seed=66621,final_normal_stress_seed=66622,features='Unchanged 40 engineered inputs',
        temporal='Refit normal-only Ridge heads using chronological out-of-fold upstream risks; 7 inputs, 3 random-LSTM64 layers, alpha1000, weighted15, upward error',
        policy='Fixed pair_threat ranking, independent second-largest IF-domain single-day novelty evidence; supervised queue first, max20, no padding',
        novelty_gate='Add only if calibration gains attack hosts, pooled precision>=80%, recall>=50%, >=15 accepted, each precision>=70%,recall>=40%,normal-review<=2%; otherwise disabled',
        known_scenarios='All seven attack families are now supervised known classes. No claim of unseen-family testing.',
        limitation='All generated populations share attack mechanisms; new seeds are not independent real-world validation',
        immutable_old_models={str(p):sha(p) for p in [v2_path(),prior_policy_path()]})
    save('protocol.json',protocol);log('protocol_recorded',**protocol)
    pairs=[cohort(s,'train',stress=s in protocol['clustered_training_seeds']) for s in protocol['training_seeds']]
    X=pd.concat([p[0] for p in pairs],ignore_index=True);M=pd.concat([p[1] for p in pairs],ignore_index=True)
    assert set(M.scenario_label)==set(CLASSES)
    assert not M.duplicated(['hostname','date']).any()
    thashes=set(pd.util.hash_pandas_object(X,index=False));assert len(thashes)==len(X)
    log('training_input_checked',rows=len(X),classes=M.scenario_label.value_counts().to_dict())
    domain=DomainStage().fit(X,M,np.ones(len(M),bool));F,rr,peak=domain.transform(X,M,'level')
    boosters=[fit_booster(F,M,np.ones(len(M),bool),SPEC,s) for s in [20261021,20261022]]
    log('eight_class_boosters_fit',normal_if_fit=domain.fit_rows,normal_if_calibration=domain.calibration_rows)
    oofthreat=np.full(len(M),np.nan);oofrisk=oofthreat.copy()
    for lo,hi in [(25,42),(42,60)]:
        fit=M.day_index.le(lo).to_numpy();target=M.day_index.gt(lo).to_numpy()&M.day_index.le(hi).to_numpy()
        dom=DomainStage().fit(X,M,fit);ff,risk,_=dom.transform(X,M,'level');model=fit_booster(ff,M,fit,SPEC)
        p=model.predict_proba(ff);oofthreat[target]=1-p[target,0];oofrisk[target]=risk[target]
        log('chronological_upstream_fold',fit_through_day=lo,target_through_day=hi,all_eight_classes_fit=True)
    fused=.85*oofthreat+.15*oofrisk;seq,target,idx,hist=windows(fused,M)
    clean=M.binary_label.to_numpy()[idx]==0;clean&=np.all(M.binary_label.to_numpy()[hist]==0,axis=1)
    blocks=np.where(M.day_index.to_numpy()<=42,0,1);clean&=np.all(blocks[hist]==blocks[idx,None],axis=1)
    import torch
    torch.set_num_threads(2);rv=rvfl_class()(input_features=1,hidden_size=64,num_layers=3,ridge_alpha=1000.,seed=20261021)
    rv.fit(seq[clean],target[clean]);log('temporal_refit',normal_forward_windows=int(clean.sum()))
    bundle=dict(domain=domain,representation='level',boosters=boosters,redrvfl=rv,fusion='weighted15',error_mode='upward',classes=CLASSES,spec=SPEC)
    cal=[cohort(s,'calibration',stress=s in protocol['clustered_calibration_seeds']) for s in protocol['calibration_seeds']]
    caldaily=[(daily(bundle,x,m)[0],m) for x,m in cal]
    frames=[host_table(d,m) for d,m in caldaily]
    selected,supervised=calibrate(frames);policy=selected['policy'];thresholds={c:daily_cutoff(caldaily,c) for c in ['threat_probability','drift_error']}
    # Faithful RedRVFL-error ranking is exported separately from review policy.
    hostvalues=np.concatenate([r.v2_error.to_numpy() for r,y in frames]);best=None
    for t in np.unique(hostvalues):
        ms=[metric(r,r[r.v2_error>=t],y) for r,y in frames]
        if any(m['normal_review_rate']>.03 for m in ms):continue
        key=(min(m['balanced_accuracy'] for m in ms),np.mean([m['balanced_accuracy'] for m in ms]),float(t))
        if best is None or key>best[0]:best=key,float(t)
    thresholds['host_error']=best[1];bundle['thresholds']=thresholds;bundle['review_policy']=policy
    joblib.dump(bundle,OUT/'pipeline.joblib')
    frozen=dict(timestamp=datetime.now(timezone.utc).isoformat(),model_sha256=sha(OUT/'pipeline.joblib'),classes=CLASSES,
        review_policy=policy,thresholds=thresholds,calibration=selected,supervised_only_calibration=supervised,
        novelty_enabled=policy['novelty_cutoff'] is not None,protocol_sha256=sha(OUT/'protocol.json'))
    save('frozen.json',frozen);log('frozen_before_final_generation',**frozen)
    evaluations={}
    old=joblib.load(v2_path())
    def evaluate(name,x,m):
        folder=OUT/name;folder.mkdir(exist_ok=True)
        d,features,p=daily(bundle,x,m);r,y=host_table(d,m);ranked,queue=chosen(r,policy)
        truth=r.merge(y,on='hostname');d.to_csv(folder/'daily_predictions.csv',index=False)
        m.to_csv(folder/'evaluation_truth.csv',index=False);ranked.to_csv(folder/'host_rankings.csv',index=False);queue.to_csv(folder/'review_queue.csv',index=False)
        errorrank=r.sort_values(['v2_error','hostname'],ascending=[False,True]);errorrank.to_csv(folder/'temporal_error_ranking.csv',index=False)
        named=classification_report(m.scenario_label,d.predicted_scenario,labels=CLASSES,output_dict=True,zero_division=0)
        result=dict(rows=len(m),scenario_classification=named,scenario_confusion_matrix=confusion_matrix(m.scenario_label,d.predicted_scenario,labels=CLASSES).tolist(),
            daily_threat=binary(m.binary_label,d.threat_probability.to_numpy(),thresholds['threat_probability']),
            daily_temporal=binary(m.binary_label,d.drift_error.to_numpy(),thresholds['drift_error']),
            accepted=metric(r,queue,y),temporal_threshold=metric(r,r[r.v2_error>=thresholds['host_error']],y),
            supervised_only=metric(r,chosen(r,supervised['policy'])[1],y),novelty_review_count=int(queue.review_route.eq('anomaly_without_class_confirmation').sum()),top_k={})
        od,_,op=daily(old,x,m);orr,oy=host_table(od,m);oldrank=orr.sort_values(['v2_error','hostname'],ascending=[False,True])
        result['old_v2_same_review_count']=metric(orr,oldrank.head(len(queue)),oy)
        result['old_v2_daily_threat']=binary(m.binary_label,od.threat_probability.to_numpy(),old['thresholds']['threat'])
        result['old_v2_daily_temporal']=binary(m.binary_label,od.drift_error.to_numpy(),old['thresholds']['drift'])
        result['old_v2_scenario_recall']={c:float((od.loc[m.scenario_label.eq(c).to_numpy(),'predicted_scenario']==c).mean()) for c in ['HONEYTOKEN_TRIP','KILL_CHAIN_APT']}
        for k in [5,10,15,20,30]:result['top_k'][k]=dict(old_v2=metric(orr,oldrank.head(k),oy),eight_class_temporal=metric(r,errorrank.head(k),y),eight_class_pair=metric(r,r.sort_values(['pair_threat','hostname'],ascending=[False,True]).head(k),y),accepted=metric(r,chosen(r,policy,k)[1],y))
        result['family_review_recall']={}
        for c in CLASSES[1:]:
            hosts=truth[truth.attack_families.fillna('').str.split('|',regex=False).map(lambda fs:c in fs)].hostname
            result['family_review_recall'][c]=dict(hosts=len(hosts),found=int(hosts.isin(queue.hostname).sum()))
        evaluations[name]=result;log('evaluation',population=name,accepted=result['accepted'],scenario_macro_f1=named['macro avg']['f1-score'],new_scenarios={c:named[c] for c in CLASSES[-2:]})
        return d,features,p,r,queue
    evaluate('training',X,M)
    for i,(x,m) in enumerate(cal):evaluate(f'calibration_{protocol["calibration_seeds"][i]}',x,m)
    # No evaluation example or outcome existed before the freeze above.
    final=[]
    for seed,role,stress in [(protocol['final_standard_seed'],'final_standard',False),(protocol['final_normal_stress_seed'],'final_normal_stress',True)]:
        x,m=cohort(seed,role,stress);overlap=int(pd.util.hash_pandas_object(x,index=False).isin(thashes).sum());assert overlap==0
        assert not set(M.hostname)&set(m.hostname)
        final.append((role,x,m,evaluate(role,x,m)))
    save('evaluation.json',evaluations)
    # Exact TreeSHAP on actual ordered eight-class inputs for reviewed evidence hosts.
    import xgboost as xgb
    role,x,m,(d,features,p,r,queue)=final[0]
    selected_indices=[]
    for h in queue.hostname:
        subset=d[d.hostname.eq(h)].tail(15);selected_indices.extend(subset.nlargest(2,'threat_probability').index.tolist())
    if not selected_indices:selected_indices=list(range(8))
    selected_features=features.iloc[selected_indices];dm=xgb.DMatrix(selected_features,feature_names=list(features))
    cc=[];residual=0.
    for b in boosters:
        booster=b.get_booster();values=booster.predict(dm,pred_contribs=True,strict_shape=True);margin=booster.predict(dm,output_margin=True,strict_shape=True)
        residual=max(residual,float(np.abs(values.sum(axis=-1)-margin).max()));cc.append(values)
    mean=np.mean(cc,axis=0);np.savez_compressed(OUT/'treeshap_eight_class.npz',contributions=mean,classes=np.array(CLASSES),features=np.array(list(features)+['BIAS']))
    pd.concat([d.iloc[selected_indices][['hostname','date']].reset_index(drop=True),selected_features.reset_index(drop=True)],axis=1).to_csv(OUT/'treeshap_selected_inputs.csv',index=False)
    reloaded=joblib.load(OUT/'pipeline.joblib');repeat=daily(reloaded,x,m[['hostname','date']])[0]
    tests=dict(eight_probability_columns=p.shape[1]==8,probabilities_sum_to_one=bool(np.allclose(p.sum(axis=1),1,atol=1e-6)),
        both_new_classes_in_training=all(c in M.scenario_label.unique() for c in CLASSES[-2:]),
        label_free_reload_matches=bool(np.allclose(repeat.threat_probability,d.threat_probability)),
        final_model_hash_unchanged=sha(OUT/'pipeline.joblib')==frozen['model_sha256'],
        original_models_unchanged=all(sha(k)==v for k,v in protocol['immutable_old_models'].items()),
        all_final_exact_training_duplicates_zero=all(not pd.util.hash_pandas_object(xx,index=False).isin(thashes).any() for _,xx,mm,res in final),
        treeshap_additive_within_tolerance=residual<1e-4)
    # A low-classifier/high-anomaly fabricated score row checks the route's independence.
    probe=r.head(1).copy();probe['pair_threat']=0.;probe['novelty_score']=1.;probe['eligible']=True
    _,pq=chosen(probe,dict(supervised_cutoff=.9,novelty_cutoff=.99));tests['novelty_can_review_with_zero_classifier_score']=len(pq)==1
    # Shuffling keyed rows cannot alter predictions.
    subset=m.hostname.eq(m.hostname.iloc[0]).to_numpy();smallx=x.loc[subset].reset_index(drop=True);smallm=m.loc[subset,['hostname','date']].reset_index(drop=True)
    ref=daily(bundle,smallx,smallm)[0];order=np.random.default_rng(7).permutation(len(smallx));shuffled=daily(bundle,smallx.iloc[order].reset_index(drop=True),smallm.iloc[order].reset_index(drop=True))[0]
    joined=ref.merge(shuffled,on=['hostname','date'],suffixes=('_a','_b'))
    tests['row_order_invariance']=bool(np.allclose(joined.drift_error_a,joined.drift_error_b,equal_nan=True))
    prefix=daily(bundle,smallx.iloc[:40],smallm.iloc[:40])[0]
    tests['future_prefix_invariance']=bool(np.allclose(prefix.drift_error,ref.drift_error.iloc[:40],equal_nan=True))
    tests={k:bool(v) for k,v in tests.items()};save('checks.json',dict(tests=tests,treeshap_max_margin_residual=residual));assert all(tests.values())
    save('schema.json',dict(raw_features=list(X),model_features=list(F),classes=CLASSES))
    log('complete',seconds=round(time.time()-begin,1),tests=tests)

if __name__=='__main__':
    try:main()
    except Exception as e:log('error',error=repr(e));raise
