#!/usr/bin/env python3
"""
NetOps Autopilot Agent — يعمل على الكمبيوتر الموصول بالشبكة
هو الجسر الحقيقي بين البرنامج والأجهزة الفعلية
- يتصل بـ seed device عبر SSH / Console
- يزحف عبر LLDP/CDP حتمياً
- يجمع الأدلة الخام
- يولد الخطة وينفذ عبر Netmiko/NAPALM
"""
import argparse
import json
import sys
import os

# إضافة backend إلى المسار
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../backend"))

from app.discovery.crawler import Target, DeterministicCrawler
from app.discovery.collectors.ssh_collector import SSHCollector
from app.intent.parser import parser
from app.intent.designer import designer
from app.config.generator import generator
from app.execution.engine import ExecutionEngine

def main():
    p = argparse.ArgumentParser(description="NetOps Autopilot — Real Agent")
    p.add_argument("--seed-ip", required=True, help="IP الجهاز الموصول بالكمبيوتر")
    p.add_argument("--seed-id", default="SEED-01", help="Hostname للـ seed")
    p.add_argument("--username", default="admin")
    p.add_argument("--password", default="admin")
    p.add_argument("--vendor", default="cisco")
    p.add_argument("--intent", default="campus", help="نص وصف الشبكة المطلوبة أو preset")
    p.add_argument("--out", default="generated/", help="مجلد المخرجات")
    p.add_argument("--vault", default="vault.json", help="ملف كلمات المرور المخصصة")
    p.add_argument("--dry-run", action="store_true", help="فقط اكتشاف وتصميم بدون تنفيذ")
    args = p.parse_args()

    print(f"🔌 NetOps Autopilot Agent — Connecting to {args.seed_ip} ({args.seed_id}) ...")

    vault = {}
    if os.path.exists(args.vault):
        with open(args.vault, encoding="utf-8") as f:
            vault = json.load(f)
        print(f"🔐 Vault loaded: {len(vault)} custom credentials")

    # 1. Discovery
    print("🔍 المرحلة 1: اكتشاف حتمي عبر LLDP/CDP ...")
    seed = Target(args.seed_id, args.seed_id, args.seed_ip, args.vendor, args.username, args.password)
    crawler = DeterministicCrawler(SSHCollector())
    result = crawler.discover(seed, vault)
    print(f"✅ Devices: {len(result.devices)} | Links: {len(result.links)} | Failures: {len(result.failures)}")
    if result.failures:
        print("⚠️  إخفاقات صريحة (مستثناة من الاستنتاجات):")
        for f in result.failures:
            print(f"  - {f}")

    # 2. Intent
    print(f"🧠 المرحلة 2: تحليل النية: '{args.intent}' ...")
    parsed = parser.parse(args.intent)
    if not parsed["ok"]:
        print(f"❌ {parsed['error']}")
        print(f"الاختيارات: {parsed['choices']}")
        sys.exit(1)
    intent = parsed["intent"]
    print(f"✅ Intent: {intent['preset']} routing={intent['routing']} hardening={intent['hardening']}")

    # 3. Design
    print("📐 المرحلة 3: تصميم حتمي ...")
    discovery_dict = {"devices": result.devices, "links": [l.__dict__ for l in result.links]}
    plan = designer.design(discovery_dict, intent)
    print(f"✅ Plan: {plan['hash']} — {len(plan['devices'])} devices — Roles: {', '.join(set(d['role'] for d in plan['devices']))}")

    # 4. Generate configs
    print(f"⚙️  المرحلة 4: توليد التكوينات إلى {args.out} ...")
    os.makedirs(args.out, exist_ok=True)
    outputs = generator.save(plan, args.out)
    # حفظ الطوبولوجيا والأدلة
    with open(os.path.join(args.out, "discovery.json"), "w", encoding="utf-8") as f:
        json.dump({"devices": result.devices, "links": [l.__dict__ for l in result.links], "failures": result.failures}, f, ensure_ascii=False, indent=2)
    with open(os.path.join(args.out, "evidence.json"), "w", encoding="utf-8") as f:
        json.dump(result.evidence, f, ensure_ascii=False, indent=2)
    print(f"📄 Generated {len(outputs)} device configs + plan.json + discovery.json")

    if args.dry_run:
        print("✋ Dry-run only — توقف قبل التنفيذ. راجع الملفات في generated/ ثم شغّل بدون --dry-run مع الموافقة.")
        return

    # 5. Execution (staged)
    print("🚀 المرحلة 5: تنفيذ مرحلي — Backup → Diff → Approve → Apply → Verify")
    engine = ExecutionEngine()
    targets = [Target(d["id"], d["hostname"], d["mgmtIp"], d.get("vendor","cisco"), args.username, args.password) for d in result.devices]
    
    print("  → Backup ...")
    backups = engine.backup(targets)
    print(f"  ✅ Backups in backups/ ({len(backups)} files)")

    dry = engine.dry_run(plan, targets)
    print(f"  → Dry-run: {'✅ نظيف' if dry['ok'] else '❌ issues: '+str(dry['issues'])}")
    if not dry["ok"]:
        sys.exit(2)

    diffs = engine.diff(plan, engine.backups)
    diff_path = os.path.join(args.out, "diff.patch")
    with open(diff_path, "w", encoding="utf-8") as f:
        for dev, d in diffs.items():
            f.write(f"\n=== {dev} ===\n{d}\n")
    print(f"  → Diff written to {diff_path} — راجعه قبل الموافقة")

    # بوابة نافذ
    ans = input("هل توافق على التطبيق؟ اكتب 'نافذ' للموافقة: ").strip()
    if ans != "نافذ":
        print("⛔ مرفوض — لم يتم إرسال أي أمر تعديل")
        engine.approve(False)
        sys.exit(0)
    engine.approve(True)
    
    print("  → Apply ...")
    apply_res = engine.apply(plan, targets, vault)
    print(f"  Result: {apply_res['summary']}")

    print("  → Verify ...")
    verify_res = engine.verify(plan, targets)
    print(f"  Verdict: {verify_res['acceptance']['verdict']} — {verify_res['summary']['passed']}/{verify_res['summary']['total']} checks passed")
    
    with open(os.path.join(args.out, "verification.json"), "w", encoding="utf-8") as f:
        json.dump(verify_res, f, ensure_ascii=False, indent=2)

    print("🎉 اكتمل — راجع سجل التدقيق والتقارير في generated/")

if __name__ == "__main__":
    main()
