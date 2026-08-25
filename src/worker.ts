import { HermesPollError, type ActionService } from './actions.js';
import { config } from './config.js';
import type { StateStore } from './state.js';

export function startOutboxWorker(state:StateStore,actions:ActionService,intervalMs=2_000):()=>void {
  let running=false;
  const dispatchOne=async()=>{
    const record=state.claimNextOutbox(); if(!record)return;
    try {
      const outcome=await actions.processOutboxRecord(record);
      state.completeOutboxDispatch(String(record.id),String(record.action_id),outcome.runId);
    } catch(error) {
      const message=error instanceof Error?error.message:'Dispatch failed';
      const attempts=Number(record.attempts??0)+1;
      if(attempts>=5) {
        state.deadLetterOutbox(String(record.id),String(record.action_id),message,record.kind==='hermes_run');
      } else {
        const delay=Math.min(300_000,5_000*2**Math.max(0,attempts-1));
        state.markOutboxFailed(String(record.id),message,new Date(Date.now()+delay).toISOString());
      }
      console.warn(`[artifact-actions] outbox dispatch failed action=${String(record.action_id)} attempt=${attempts}`);
    }
  };
  const pollOne=async()=>{
    const action=state.nextRunningHermesAction(); if(!action)return;
    if(Date.now()-Date.parse(action.createdAt)>config.hermesRunMaxMs){state.failHermesPolling(action.id);return;}
    try { await actions.pollHermesRun(action); }
    catch(error) { if(error instanceof HermesPollError&&error.terminal)state.failHermesPolling(action.id); else state.touchAction(action.id); }
  };
  const tick=async()=>{
    if(running)return; running=true;
    try { await dispatchOne(); await pollOne(); }
    finally { running=false; }
  };
  const timer=setInterval(()=>void tick(),intervalMs); timer.unref(); void tick();
  return ()=>clearInterval(timer);
}
