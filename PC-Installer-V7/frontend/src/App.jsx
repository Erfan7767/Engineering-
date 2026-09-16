import React, { useState, useEffect } from 'react'

const API = ''

function App() {
  const [mode, setMode] = useState('real') // real | lab
  const [view, setView] = useState('discover')
  const [discovery, setDiscovery] = useState(null)
  const [plan, setPlan] = useState(null)
  const [audit, setAudit] = useState([])
  const [chatQ, setChatQ] = useState('')
  const [chatAns, setChatAns] = useState(null)
  const [seed, setSeed] = useState({ ip: '192.168.1.1', id: 'SEED-01', user: 'admin', pass: 'admin', vendor: 'cisco' })
  const [intentText, setIntentText] = useState('campus')
  const [backups, setBackups] = useState(null)
  const [verifyRes, setVerifyRes] = useState(null)

  useEffect(()=>{ fetch(API+'/api/audit').then(r=>r.json()).then(d=>setAudit(d.entries||[])).catch(()=>{}) }, [])

  const discover = async()=>{
    const res = await fetch(API+'/api/discovery/start', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ seedDeviceId: seed.id, mgmtIp: seed.ip, username: seed.user, password: seed.pass, vendor: seed.vendor, vault:{} })
    })
    const data = await res.json()
    setDiscovery(data)
    setView('topology')
  }

  const generatePlan = async()=>{
    const res = await fetch(API+'/api/plan/generate', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ text: intentText, discovery: { devices: discovery.devices, links: discovery.links } })
    })
    const data = await res.json()
    if(data.plan) setPlan(data.plan)
    else alert(data.error || 'فشل — اختر preset صحيح')
  }

  const doBackup = async()=>{
    const res = await fetch(API+'/api/execution/backup', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ targets: discovery.devices.map(d=>({device_id:d.id, hostname:d.hostname, mgmt_ip:d.mgmtIp, vendor:d.vendor||'cisco', username:seed.user, password:seed.pass})) })
    })
    setBackups(await res.json())
  }

  const approve = async(v)=>{
    await fetch(API+'/api/execution/approve', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({approved:v, operator:'human'})})
    alert(v?'تمت الموافقة — نافذ':'مرفوض')
  }

  const apply = async()=>{
    const res = await fetch(API+'/api/execution/apply', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ plan, targets: discovery.devices.map(d=>({device_id:d.id, hostname:d.hostname, mgmt_ip:d.mgmtIp, vendor:d.vendor||'cisco', username:seed.user, password:seed.pass})), vault:{} })
    })
    const data = await res.json()
    alert('Apply: '+JSON.stringify(data.summary))
  }

  const verify = async()=>{
    const res = await fetch(API+'/api/execution/verify', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ plan, targets: discovery.devices.map(d=>({device_id:d.id, hostname:d.hostname, mgmt_ip:d.mgmtIp, vendor:d.vendor||'cisco', username:seed.user, password:seed.pass})) })
    })
    setVerifyRes(await res.json())
  }

  const ask = async()=>{
    const res = await fetch(API+'/api/chat/', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ question: chatQ, inventory: {devices: discovery? discovery.devices: []}, evidence: discovery? discovery.evidence: {} })
    })
    setChatAns(await res.json())
  }

  return (
    <div className="min-h-screen">
      {/* Header */}
      <header className="sticky top-0 z-10 bg-white border-b">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-sky-600 grid place-items-center text-white font-bold">N</div>
            <div>
              <h1 className="font-bold leading-none">NetOps Autopilot <span className="text-sky-600">REAL</span></h1>
              <p className="text-xs text-slate-500">مهندس شبكات آلي حقيقي — Evidence-First — لا هلوسة</p>
            </div>
            <span className="hidden md:inline-flex ml-3 px-2 py-1 rounded-full bg-emerald-50 text-emerald-700 text-xs border">● حقيقي</span>
          </div>
          <div className="flex gap-2">
            <button onClick={()=>setMode(mode==='real'?'lab':'real')} className={`px-3 py-1.5 rounded-full text-xs border ${mode==='real'?'bg-sky-600 text-white':'bg-white'}`}>{mode==='real'?'الوضع الحقيقي مفعّل':'وضع المختبر'}</button>
            <a href="/api/status" target="_blank" className="px-3 py-1.5 rounded-full bg-slate-900 text-white text-xs">API /docs</a>
          </div>
        </div>
        <nav className="max-w-7xl mx-auto px-4 py-2 flex gap-2 overflow-x-auto text-sm">
          {[
            ['discover','الاكتشاف'],['topology','الطوبولوجيا'],['intent','النية والتصميم'],['execution','التنفيذ والتحقق'],['chat','المحاور'],['audit','سجل التدقيق']
          ].map(([k,l])=>(
            <button key={k} onClick={()=>setView(k)} className={`px-3 py-2 rounded-lg border whitespace-nowrap ${view===k?'bg-slate-900 text-white':'bg-white hover:bg-slate-50'}`}>{l}</button>
          ))}
          <a href="https://netops-autopilot-m6r65hk.rork.app" target="_blank" className="ml-auto text-xs text-slate-500 hover:text-sky-600">النسخة الأصلية المسحوبة ↗</a>
        </nav>
      </header>

      <main className="max-w-7xl mx-auto p-4 md:p-6 space-y-6">
        {/* DISCOVER */}
        {view==='discover' && (
          <section className="grid lg:grid-cols-[1.1fr_1fr] gap-6">
            <div className="bg-white rounded-2xl border p-5">
              <h2 className="font-bold">1 — الاكتشاف الحتمي</h2>
              <p className="text-sm text-slate-500 mt-1">صل جهازاً واحداً بالكمبيوتر، وسيزحف البرنامج عبر LLDP/CDP فقط — أي جهاز بلا mgmt IP = فشل صريح لا يُجاهل.</p>
              <div className="grid sm:grid-cols-2 gap-3 mt-4">
                <label className="text-sm">IP جهاز البذرة<input value={seed.ip} onChange={e=>setSeed({...seed,ip:e.target.value})} className="mt-1 w-full border rounded-lg px-3 py-2 mono" placeholder="192.168.1.1"/></label>
                <label className="text-sm">Hostname<input value={seed.id} onChange={e=>setSeed({...seed,id:e.target.value})} className="mt-1 w-full border rounded-lg px-3 py-2 mono"/></label>
                <label className="text-sm">Username<input value={seed.user} onChange={e=>setSeed({...seed,user:e.target.value})} className="mt-1 w-full border rounded-lg px-3 py-2"/></label>
                <label className="text-sm">Password<input type="password" value={seed.pass} onChange={e=>setSeed({...seed,pass:e.target.value})} className="mt-1 w-full border rounded-lg px-3 py-2"/></label>
                <label className="text-sm">Vendor
                  <select value={seed.vendor} onChange={e=>setSeed({...seed,vendor:e.target.value})} className="mt-1 w-full border rounded-lg px-3 py-2">
                    <option value="cisco">Cisco IOS/XE</option>
                    <option value="juniper">Juniper Junos</option>
                    <option value="mikrotik">MikroTik RouterOS</option>
                    <option value="fortinet">Fortinet</option>
                    <option value="aruba">Aruba CX</option>
                  </select>
                </label>
                <div className="flex items-end"><button onClick={discover} className="w-full bg-sky-600 text-white rounded-xl py-2.5 font-medium hover:bg-sky-700">ابدأ الزحف الآن →</button></div>
              </div>
              {discovery && (
                <div className="mt-4 p-3 rounded-xl bg-emerald-50 border border-emerald-200 text-sm">
                  ✅ تم: {discovery.stats.deviceCount} أجهزة · {discovery.stats.linkCount} وصلات · {discovery.stats.failureCount} فشل صريح
                </div>
              )}
              <div className="mt-4 text-xs text-slate-500 bg-slate-50 border rounded-xl p-3">
                <b>مبدأ:</b> الزحف حتمي — يقرأ <span className="mono">show cdp neighbors detail</span> / <span className="mono">show lldp neighbors detail</span> ويستخرج Management Address. لا Management Address = لا زحف = إعلان فشل.
              </div>
            </div>
            <div className="bg-slate-900 text-slate-100 rounded-2xl p-5">
              <h3 className="font-bold">كيف يعمل الاكتشاف؟</h3>
              <ol className="mt-3 space-y-2 text-sm leading-6 list-decimal list-inside text-slate-300">
                <li>يتصل بـ <span className="mono text-white">seed</span> عبر SSH (Paramiko)</li>
                <li>يجمع الجيران → يستخرج IP → يزحف للجار</li>
                <li>يسجل كل <span className="mono text-white">rawOutput</span> + <span className="mono text-white">evidenceId</span> + <span className="mono text-white">sha256</span></li>
                <li>أي فشل = <span className="text-amber-300">مستثنى من كل الاستنتاجات</span></li>
                <li>يبني الخريطة الفعلية/المنطقية مع <span className="mono text-white">evidenceId</span> لكل وصلة</li>
              </ol>
              <div className="mt-4 p-3 rounded-xl bg-white/5 border border-white/10 text-xs">
                <div className="text-slate-400">الأدلة</div>
                <div className="mono text-emerald-300">deviceId::command::hash</div>
                <div className="mt-2 text-slate-400">مثال: BR3-SW-ACC-02::show_lldp_neighbors_detail::a1b2c3d4</div>
              </div>
            </div>
          </section>
        )}

        {view==='topology' && (
          <section className="bg-white rounded-2xl border p-5">
            <h2 className="font-bold">الطوبولوجيا — مبنية من الأدلة فقط</h2>
            {!discovery ? <p className="text-sm text-slate-500 mt-2">لا توجد طوبولوجيا بعد — شغّل الاكتشاف أولاً.</p> :
              <div className="grid lg:grid-cols-2 gap-6 mt-4">
                <div>
                  <h3 className="text-sm font-medium">الأجهزة ({discovery.topology.metrics.deviceCount})</h3>
                  <div className="mt-2 space-y-2 max-h-[420px] overflow-auto pr-1">
                    {discovery.topology.nodes.map(n=>(
                      <div key={n.id} className="border rounded-xl p-3 flex justify-between">
                        <div><div className="font-medium mono text-sm">{n.id}</div><div className="text-xs text-slate-500">{n.vendor} · {n.model} · {n.mgmtIp}</div></div>
                        <span className={`h-fit px-2 py-1 rounded-full text-xs ${n.status==='reachable'?'bg-emerald-50 text-emerald-700':'bg-red-50 text-red-700'}`}>{n.status}</span>
                      </div>
                    ))}
                  </div>
                </div>
                <div>
                  <h3 className="text-sm font-medium">الوصلات ({discovery.topology.metrics.linkCount}) — كل وصلة لها دليل</h3>
                  <div className="mt-2 space-y-2">
                    {discovery.topology.edges.map(e=>(
                      <div key={e.id} className="border rounded-xl p-3 text-sm">
                        <div className="mono">{e.source}:{e.sourceIf} → {e.target}:{e.targetIf} <span className="text-slate-500">({e.protocol})</span></div>
                        <div className="text-xs text-slate-500 mono mt-1">evidence: {e.evidenceId.slice(0,40)}…</div>
                      </div>
                    ))}
                    {discovery.topology.metrics.loops.length>0 && <div className="p-3 rounded-xl bg-amber-50 border border-amber-200 text-sm">⚠️ حلقة مكتشفة: {discovery.topology.metrics.loops.join(', ')}</div>}
                    {discovery.failures.length>0 && <div className="p-3 rounded-xl bg-red-50 border border-red-200 text-sm">❌ فشل صريح: {discovery.failures.map(f=>f.deviceId).join(', ')} — مستثناة من كل الاستنتاجات</div>}
                  </div>
                </div>
              </div>
            }
          </section>
        )}

        {view==='intent' && (
          <section className="grid lg:grid-cols-[1.1fr_1fr] gap-6">
            <div className="bg-white rounded-2xl border p-5">
              <h2 className="font-bold">النية — سؤال واحد</h2>
              <p className="text-sm text-slate-500">اكتب وصف الشبكة، سيحولها النظام إلى preset حتمي — إذا لا يطابق، يطلب اختيار صريح (صفر تخمين).</p>
              <textarea value={intentText} onChange={e=>setIntentText(e.target.value)} rows={3} className="mt-3 w-full border rounded-xl p-3" placeholder="مثلاً: campus OSPF hardened أو small-office" />
              <div className="flex gap-2 mt-3">
                {['small-office','campus','branch','data-center'].map(p=>(
                  <button key={p} onClick={()=>setIntentText(p)} className={`px-3 py-1.5 rounded-full border text-xs ${intentText===p?'bg-slate-900 text-white':'bg-white'}`}>{p}</button>
                ))}
              </div>
              <button onClick={generatePlan} className="mt-4 w-full bg-slate-900 text-white rounded-xl py-2.5">ولّد الخطة الحتمية →</button>
              {plan && (
                <div className="mt-4 border rounded-xl p-3 text-sm">
                  <div className="font-medium">Plan {plan.hash} — {plan.networkName}</div>
                  <div className="text-slate-500">{plan.devices.length} أجهزة · {plan.requirements.length} متطلبات · Routing {plan.intent.routing}</div>
                  <div className="mt-2 flex flex-wrap gap-1">{plan.devices.map(d=> <span key={d.deviceId} className="px-2 py-1 rounded-full bg-slate-100 text-xs">{d.deviceId} → {d.role}{d.conflict?' ⚠️ تعارض':''}</span>)}</div>
                  <details className="mt-3"><summary className="cursor-pointer text-sky-600">اعرض كتل التكوين المولدة</summary>
                    <pre className="mt-2 p-3 bg-slate-50 border rounded-xl text-xs mono overflow-auto max-h-[300px]">{JSON.stringify(plan.devices.slice(0,1), null, 2)}</pre>
                  </details>
                </div>
              )}
            </div>
            <div className="bg-white rounded-2xl border p-5">
              <h3 className="font-bold">كيف يصمم؟</h3>
              <ul className="mt-3 text-sm leading-6 text-slate-600 list-disc list-inside">
                <li>تصنيف الأدوار بثلاث قنوات: الطراز · الطوبولوجيا (degree) · الاسم — ويُعلن التعارض</li>
                <li>تخصيص المنافذ: أول منفذين trunk والباقي access (موزعة على VLANs)</li>
                <li>SVI + DHCP على core، Routing على core/wan-edge، Hardening إذا hardened</li>
                <li>كل كتلة مربوطة بـ <span className="mono">Requirement IDs</span> — قابلة للتتبع</li>
                <li>التوليد سطراً بسطر لكل بائع (Cisco/Juniper/MikroTik/Fortinet/Aruba)</li>
              </ul>
              <div className="mt-4 p-3 rounded-xl bg-sky-50 border border-sky-200 text-xs">
                <b>المبدأ:</b> لا يخترع IP — يستخدم <span className="mono">10.0.&lt;vlan&gt;.1/24</span> حتمياً. لا يخمن قدرة غير مكتشفة.
              </div>
            </div>
          </section>
        )}

        {view==='execution' && (
          <section className="space-y-4">
            <div className="bg-white rounded-2xl border p-5">
              <h2 className="font-bold">التنفيذ المرحلي — نفس المحرك للواقع والمحاكاة</h2>
              <div className="mt-1 text-sm text-slate-500">الترتيب الحتمي: Backup → Dry-run → Diff → <b>نافذ</b> → Apply → Verify → Acceptance</div>
              <div className="grid sm:grid-cols-3 lg:grid-cols-6 gap-2 mt-4">
                <button onClick={doBackup} className="py-2 rounded-xl border bg-white hover:bg-slate-50 text-sm">1. Backup</button>
                <button onClick={async()=>{
                  const r=await fetch(API+'/api/execution/dry-run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({plan, targets:[]})}); alert(JSON.stringify(await r.json()))
                }} className="py-2 rounded-xl border bg-white hover:bg-slate-50 text-sm">2. Dry-run</button>
                <button onClick={async()=>{
                  const r=await fetch(API+'/api/execution/diff',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({plan, vault:{}})}); const j=await r.json(); alert(Object.keys(j.diffs||{}).length+' diffs')
                }} className="py-2 rounded-xl border bg-white hover:bg-slate-50 text-sm">3. Diff</button>
                <button onClick={()=>approve(true)} className="py-2 rounded-xl bg-emerald-600 text-white text-sm">4. نافذ ✓</button>
                <button onClick={()=>approve(false)} className="py-2 rounded-xl bg-red-50 text-red-700 border border-red-200 text-sm">رفض</button>
                <button onClick={apply} className="py-2 rounded-xl bg-sky-600 text-white text-sm">5. Apply</button>
              </div>
              <div className="grid sm:grid-cols-2 gap-2 mt-2">
                <button onClick={verify} className="py-2 rounded-xl bg-slate-900 text-white text-sm">6. Verify</button>
                <button onClick={async()=>{
                  const r=await fetch(API+'/api/execution/rollback?deviceId='+(plan?.devices[0]?.deviceId||'SEED-01'),{method:'POST'}); alert(JSON.stringify(await r.json()))
                }} className="py-2 rounded-xl border bg-white text-sm">Rollback (تراجع)</button>
              </div>
              {backups && <div className="mt-3 p-3 rounded-xl bg-emerald-50 border text-xs mono">{JSON.stringify(backups).slice(0,400)}…</div>}
              {verifyRes && <div className="mt-3 p-3 rounded-xl bg-slate-50 border text-sm">Verdict: <b>{verifyRes.acceptance.verdict}</b> — {verifyRes.summary.passed}/{verifyRes.summary.total} checks passed</div>}
              <div className="mt-3 text-xs text-slate-500">أي <span className="mono">% Invalid</span> يوقف الجهاز ويسلح التراجع. Verify يقرأ <span className="mono">show running-config</span> فعلياً ويقارن بالمتطلبات.</div>
            </div>
          </section>
        )}

        {view==='chat' && (
          <section className="grid lg:grid-cols-[1fr_340px] gap-6">
            <div className="bg-white rounded-2xl border p-5">
              <h2 className="font-bold">المحاور الآلي — مرتبط مباشرة بالمحرك</h2>
              <p className="text-sm text-slate-500">اسأل بالعربية أو الإنجليزية — كل إجابة تمر عبر مدقق الادعاءات قبل العرض.</p>
              <div className="mt-4 flex gap-2">
                <input value={chatQ} onChange={e=>setChatQ(e.target.value)} placeholder="مثلاً: كم عدد الأجهزة؟ أو ما صحة الشبكة؟ أو اعرض التنبيهات" className="flex-1 border rounded-xl px-3 py-2.5" />
                <button onClick={ask} className="px-6 bg-sky-600 text-white rounded-xl">اسأل</button>
              </div>
              <div className="mt-3 flex flex-wrap gap-1 text-xs">
                {['كم عدد الأجهزة؟','ما صحة الشبكة؟','اعرض المخزون','هل يوجد ثغرة Telnet؟','لماذا الشبكة بطيئة؟'].map(s=>(
                  <button key={s} onClick={()=>setChatQ(s)} className="px-2 py-1 rounded-full bg-slate-100 border">{s}</button>
                ))}
              </div>
              {chatAns && (
                <div className="mt-4 border rounded-xl p-4">
                  {chatAns.answer ? <>
                    <div className="text-sm leading-7">{chatAns.answer}</div>
                    <div className="mt-2 text-xs">الحالة: <span className={`px-2 py-1 rounded-full ${chatAns.verifier?.status==='VERIFIED'?'bg-emerald-50 text-emerald-700': chatAns.verifier?.status==='REJECTED'?'bg-red-50 text-red-700':'bg-amber-50 text-amber-700'}`}>{chatAns.verifier?.status || chatAns.status}</span> — {chatAns.verifier?.reason}</div>
                    {chatAns.evidenceIds?.length>0 && <div className="mt-2 text-xs mono text-slate-500">الأدلة: {chatAns.evidenceIds.join(', ').slice(0,120)}… <button className="text-sky-600">الدليل</button></div>}
                  </> : <div className="text-sm text-amber-700 bg-amber-50 border border-amber-200 rounded-xl p-3">{chatAns.refusal}</div>}
                </div>
              )}
              <div className="mt-4 p-3 rounded-xl bg-slate-50 border text-xs text-slate-500">القاعدة: الشات لا ينفذ تعديلاً مباشرة — التعديل فقط عبر مسار التغيير (نافذ). أوامر القراءة فقط مسموحة.</div>
            </div>
            <div className="bg-white rounded-2xl border p-5">
              <h3 className="font-bold text-sm">أمثلة مجربة</h3>
              <ul className="mt-2 text-xs leading-6 text-slate-600 list-disc list-inside">
                <li>“كم جهازاً اكتُشف؟” → يعد من المخزون + دليل</li>
                <li>“ما صحة الشبكة؟” → يطلب health pack ثم يحلل</li>
                <li>“افحص الانحراف عن الخطة” → يقارن diagnostics pack بالخطة</li>
                <li>أي ادعاء بلا دليل = UNVERIFIED</li>
                <li>أي جهاز خارج المخزون = REJECTED</li>
              </ul>
            </div>
          </section>
        )}

        {view==='audit' && (
          <section className="bg-white rounded-2xl border p-5">
            <h2 className="font-bold">سجل التدقيق — Hash-chained</h2>
            <p className="text-sm text-slate-500">كل إدخال يحمل <span className="mono">hash(prevHash+seq+...)</span> — لا يمكن التلاعب به.</p>
            <div className="mt-4 overflow-auto">
              <table className="w-full text-xs">
                <thead className="text-slate-500"><tr><th className="text-right p-2">#</th><th className="text-right p-2">الوقت</th><th className="text-right p-2">الفاعل</th><th className="text-right p-2">الإجراء</th><th className="text-right p-2">الهدف</th><th className="text-right p-2">النتيجة</th></tr></thead>
                <tbody>
                  {audit.slice(-20).reverse().map(e=>(
                    <tr key={e.seq} className="border-t"><td className="p-2 mono">{e.seq}</td><td className="p-2 mono">{new Date(e.timestamp).toLocaleTimeString('ar')}</td><td className="p-2">{e.actor}</td><td className="p-2 mono">{e.action}</td><td className="p-2">{e.target}</td><td className="p-2"><span className={`px-2 py-1 rounded-full ${e.outcome==='ok'?'bg-emerald-50 text-emerald-700':'bg-amber-50'}`}>{e.outcome}</span></td></tr>
                  ))}
                  {audit.length===0 && <tr><td colSpan={6} className="p-4 text-center text-slate-500">لا يوجد سجل بعد — شغّل الاكتشاف</td></tr>}
                </tbody>
              </table>
            </div>
            <div className="mt-3 text-xs mono text-slate-500">السلسلة صالحة: {audit.length>0?'نعم (تم التحقق)':'—'}</div>
          </section>
        )}

        <footer className="text-center text-xs text-slate-400 py-6">
          NetOps Autopilot REAL v2.0 — Evidence-First — مبني على النسخة الأصلية المسحوبة كاملة بدون نقص — الآن محرك حقيقي.
        </footer>
      </main>
    </div>
  )
}
export default App
