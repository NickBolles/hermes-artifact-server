import { stdin as input, stdout as output } from 'node:process';
import { createInterface } from 'node:readline/promises';
import { createAuthService } from './app-auth.js';
import { config } from './config.js';
import { createStateStore } from './state.js';

function arg(name:string):string { const index=process.argv.indexOf(name); return index>=0?process.argv[index+1]??'':''; }

async function main():Promise<void> {
  const command=process.argv[2]??'';
  if(command!=='bootstrap-admin') throw new Error('Usage: node dist/cli.js bootstrap-admin --username <name> (password on stdin)');
  const username=arg('--username'); if(!username)throw new Error('--username is required');
  let recoveryPassword=process.env.ARTIFACT_ADMIN_RECOVERY_PASSWORD??'';
  if(!recoveryPassword) {
    if(input.isTTY) throw new Error('For hidden input, run: read -s PASSWORD; printf "\\n"; printf "%s\\n" "$PASSWORD" | npm run admin:bootstrap -- --username <name>');
    const rl=createInterface({input,output,terminal:false}); recoveryPassword=(await rl.question('')).trimEnd(); rl.close();
  }
  const state=createStateStore(config.stateDbPath);
  try { const auth=createAuthService(state); const id=await auth.bootstrapAdmin({username,recoveryPassword}); output.write(`Bootstrapped admin ${username} (${id}). Sign in through Recover account and register a passkey.\n`); }
  finally { state.close(); }
}

main().catch((error)=>{console.error(error instanceof Error?error.message:'Bootstrap failed');process.exitCode=1});
