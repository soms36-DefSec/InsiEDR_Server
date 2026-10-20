"""Four domains, exactly 40 inputs, eight probabilities, seven-day temporal model.

All transformations are label-free; labels are used only by fit/calibration/evaluation.
"""
from pathlib import Path
import sys,hashlib,importlib.util
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier

CLASSES=['BENIGN','CLOUD_EXFILTRATION_PRECURSOR','CREDENTIAL_DUMP','DATA_HOARDING','IT_SABOTAGE','USB_EXFILTRATION_PRECURSOR','HONEYTOKEN_TRIP','KILL_CHAIN_APT']
OMIT=['mean_session_duration_seconds','usb_disconnect_count','unique_filename_count','unique_domain_count','peak_process_count','unique_remote_ip_count','wmi_query_count','dns_query_count']
GROUPS={'identity':list(range(8)),'device_file':list(range(8,18)),
        'web_network':list(range(18,24))+list(range(28,32))+[38,39],
        'execution':list(range(24,28))+list(range(32,38))}
RELATIVE={'successful_logons','failed_logons','unique_pc_count','interactive_duration_seconds','usb_connect_count',
          'distinct_usb_devices','file_access_count','new_filename_count','http_request_count','new_domain_count',
          'mean_process_count','bytes_sent','bytes_received','external_connection_count','clipboard_copy_count','named_pipe_event_count'}

def history(values,meta):
    v=pd.DataFrame(values).reset_index(drop=True)
    ordered=meta.assign(_p=np.arange(len(meta))).sort_values(['hostname','date'])
    dates=pd.to_datetime(ordered.date)
    seg=(ordered.hostname.ne(ordered.hostname.shift())|dates.diff().dt.days.ne(1)).cumsum().to_numpy()
    a=v.iloc[ordered._p].reset_index(drop=True).groupby(seg,sort=False).shift(1)
    mean=a.groupby(seg,sort=False).transform(lambda c:c.rolling(7,min_periods=3).mean())
    std=a.groupby(seg,sort=False).transform(lambda c:c.rolling(7,min_periods=3).std())
    for frame in [mean,std]:frame.index=ordered._p.to_numpy()
    return mean.sort_index().to_numpy(),std.sort_index().to_numpy()

class DomainStage:
    def fit(self,X,M,mask):
        self.columns=list(X);self.base=[c for c in X if c not in OMIT]
        assert len(self.columns)==40 and len(self.base)==32
        clean=np.asarray(mask)&M.binary_label.eq(0).to_numpy()
        hostcal=M.hostname.map(lambda h:int(hashlib.sha256(h.encode()).hexdigest()[:8],16)%5==0).to_numpy()
        fit=clean&~hostcal;cal=clean&hostcal
        if fit.sum()<100 or cal.sum()<100:raise ValueError('Insufficient train-only normal fit/calibration rows')
        self.fit_rows=int(fit.sum());self.calibration_rows=int(cal.sum())
        logs=np.log1p(X.to_numpy(float));self.models={};self.reference={}
        for name,indices in GROUPS.items():
            forest=IsolationForest(n_estimators=180,max_samples=512,n_jobs=2,random_state=20261021)
            forest.fit(logs[fit][:,indices]);self.models[name]=forest
            self.reference[name]=np.sort(-forest.score_samples(logs[cal][:,indices]))
        return self
    def transform(self,X,M,representation):
        if list(X)!=self.columns:raise ValueError('Wrong raw column order')
        values=X.to_numpy(float)
        if not np.isfinite(values).all() or (values<0).any():raise ValueError('Invalid numeric inputs')
        if M.duplicated(['hostname','date']).any():raise ValueError('Duplicate host/date')
        if len(X)!=len(M):raise ValueError('Unaligned metadata')
        logged=np.log1p(values);scores=[]
        for name,indices in GROUPS.items():
            raw=-self.models[name].score_samples(logged[:,indices]);ref=self.reference[name]
            percentile=np.searchsorted(ref,raw,side='right')/len(ref)
            scores.append(np.clip((percentile-.90)/.10,0,1))
        scores=np.column_stack(scores);risk=scores.mean(axis=1)
        base=np.log1p(X[self.base].to_numpy(float))
        if representation!='level':
            mean,std=history(base,M)
            delta=np.nan_to_num(np.clip((base-mean)/np.maximum(std,.25),-8,8))
            if representation=='context':base=delta
            elif representation=='hybrid':
                rel=np.array([c in RELATIVE for c in self.base]);base[:,rel]=delta[:,rel]
            else:raise ValueError(representation)
        frame=pd.DataFrame(base,columns=[representation+'__'+c for c in self.base])
        for i,name in enumerate(GROUPS):frame['if_'+name]=scores[:,i]
        mean,std=history(risk[:,None],M)
        frame['if_weighted_risk']=risk
        frame['past7_risk_mean']=np.nan_to_num(mean[:,0]);frame['past7_risk_std']=np.nan_to_num(std[:,0])
        frame['risk_minus_past7_mean']=np.where(np.isfinite(mean[:,0]),risk-mean[:,0],0)
        assert frame.shape[1]==40 and np.isfinite(frame.to_numpy()).all()
        return frame,risk,scores.max(axis=1)

def new_booster(spec,seed):
    return XGBClassifier(objective='multi:softprob',num_class=len(CLASSES),eval_metric='mlogloss',
       tree_method='hist',n_estimators=spec['trees'],max_depth=spec['depth'],learning_rate=.035,
       min_child_weight=spec['child'],reg_lambda=40,reg_alpha=3,gamma=.5,
       subsample=.75,colsample_bytree=.8,random_state=seed,n_jobs=2)

def fit_booster(F,M,mask,spec,seed=20261021):
    y=M.loc[mask,'scenario_label'].map({c:i for i,c in enumerate(CLASSES)})
    if y.isna().any() or set(y)!=set(range(len(CLASSES))):raise ValueError('All eight classes required')
    count=np.bincount(y.astype(int),minlength=len(CLASSES))
    w=np.minimum(len(y)/(len(CLASSES)*count),spec['weight_cap'])[y.astype(int)]
    model=new_booster(spec,seed);model.fit(F.loc[mask],y.astype(int),sample_weight=w)
    return model

def windows(risk,M):
    indices=[];hist=[]
    ordered=M.assign(_p=np.arange(len(M))).sort_values(['hostname','date'])
    for _,g in ordered.groupby('hostname',sort=False):
        idx=g._p.to_numpy();dates=pd.to_datetime(g.date).to_numpy()
        for j in range(7,len(g)):
            eight=idx[j-7:j+1]
            if np.all(np.diff(dates[j-7:j+1]).astype('timedelta64[D]').astype(int)==1) and np.isfinite(risk[eight]).all():
                indices.append(idx[j]);hist.append(eight[:-1])
    idx=np.array(indices,int);h=np.array(hist,int).reshape(-1,7)
    return np.asarray(risk)[h,None].astype(np.float32),np.asarray(risk)[idx],idx,h

def rvfl_class():
    if 'reference_redrvfl' not in sys.modules:
        spec=importlib.util.spec_from_file_location('reference_redrvfl',Path(__file__).with_name('reference_redrvfl.py'))
        module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    return sys.modules['reference_redrvfl'].RedRVFLOrchestrator

def fuse(threat,if_mean,if_peak,mode):
    # Tailed IF scores can support novelty detection without imposing a .5 normal floor.
    if mode=='weighted15':return .85*threat+.15*if_mean
    if mode=='weighted35':return .65*threat+.35*if_mean
    if mode=='novelty':return np.maximum(.85*threat+.15*if_mean,.5*if_peak)
    if mode=='reference':return np.maximum(if_mean,.3*if_mean+.7*threat)
    raise ValueError(mode)

def drift(fused,pred,error_mode):
    return np.abs(fused-pred) if error_mode=='absolute' else np.maximum(fused-pred,0)

def score(bundle,X,M):
    F,risk,peak=bundle['domain'].transform(X,M,bundle['representation'])
    probs=np.mean([m.predict_proba(F) for m in bundle['boosters']],axis=0)
    fused=fuse(1-probs[:,0],risk,peak,bundle['fusion'])
    seq,_,idx,_=windows(fused,M)
    pred=np.full(len(M),np.nan);error=pred.copy()
    if len(idx):
        pred[idx]=np.clip(bundle['redrvfl'].predict(seq),0,1)
        error[idx]=drift(fused[idx],pred[idx],bundle['error_mode'])
    return F,risk,probs,fused,pred,error

def host_rank(M,error,last15=False):
    records=[]
    frame=M.copy();frame['error']=error
    for host,g in frame.sort_values('date').groupby('hostname'):
        usable=g.loc[g.error.notna()]
        if last15:usable=usable.tail(15)
        n=len(usable);eligible=n==15 if last15 else n>0
        r=dict(hostname=host,sequence_count=n,score=float(usable.error.max()*usable.error.mean()*np.sqrt(n)) if eligible else np.nan,
               eligible=eligible,ranking_start=usable.date.min() if n else None,ranking_end=usable.date.max() if n else None)
        if 'binary_label' in M:r['binary_label']=int(usable.binary_label.max()) if n else int(g.binary_label.max())
        records.append(r)
    rank=pd.DataFrame(records).sort_values('score',ascending=False,na_position='last').reset_index(drop=True)
    rank.insert(0,'rank',np.arange(1,len(rank)+1));return rank
