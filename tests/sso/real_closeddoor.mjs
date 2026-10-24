// Real provider verification without creating or unlocking a vault.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { createRequire } from 'node:module'
const req=createRequire(import.meta.url)
const { chromium }=req(req.resolve('playwright',{paths:(process.env.NODE_PATH||'').split(':')}))
const { VAULT,SSO,SEED,VAULT_DB }=process.env
const seed=JSON.parse(readFileSync(SEED,'utf8'))
const browser=await chromium.launch()
try {
 const ctx=await browser.newContext();const page=await ctx.newPage()
 await page.goto(VAULT+'/login'); await page.getByText('Sign in with ClosedDoor').click()
 await page.waitForURL(SSO+'/**');await page.locator('#email').fill(seed.email);await page.locator('#password').fill(seed.password);await page.locator('button[type=submit]').click()
 await page.waitForURL(VAULT+'/**');await page.locator('nav[aria-label="Your apps"] a[href="https://notes.example/"]').waitFor()
 const response=await ctx.request.get(VAULT+'/api/v1/session');assert.equal(response.status(),200)
 const session=await response.json();assert.equal(session.vault.state,'none');assert.equal(session.apps.length,1);assert.equal(session.user.role,'admin')
 assert.equal(await page.getByRole('link',{name:'Download Chrome extension'}).count(),1)
 const zip=await ctx.request.get(VAULT+'/download/extension.zip');assert.equal(zip.status(),200);assert.equal((await zip.body()).subarray(0,2).toString(),'PK')
 const expire=()=>execFileSync('python3',['-c','import sqlite3,sys;c=sqlite3.connect(sys.argv[1]);c.execute("UPDATE sessions SET checked_at=0");c.commit()',VAULT_DB])
 execFileSync('mysql',['-e',`DELETE FROM user_client_access WHERE user_id=${seed.uid} AND client_pk=${seed.notes_pk}`]);expire();await page.reload()
 await page.getByRole('link',{name:'Download Chrome extension'}).waitFor();assert.equal(await page.locator('nav[aria-label="Your apps"]').count(),0)
 execFileSync('mysql',['-e',`UPDATE users SET active=0 WHERE id=${seed.uid}`]);expire();assert.equal((await ctx.request.get(VAULT+'/api/v1/session')).status(),401)
 await ctx.close();console.log('Real ClosedDoor SSO, locked rail, authenticated Chrome ZIP and grant/session revocation passed')
} finally {await browser.close()}
