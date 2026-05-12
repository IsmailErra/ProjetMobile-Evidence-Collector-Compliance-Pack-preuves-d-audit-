import os
import sys
import hashlib
import re
import json
import datetime
import zipfile
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Tentative d'import d'androguard (Compatible v3 et v4)
try:
    # Androguard 4.x
    from androguard.core.apk import APK
    from androguard.core.axml import AXMLPrinter
    ANDROGUARD_OK = True
except ImportError:
    try:
        # Androguard 3.x
        from androguard.core.bytecodes.apk import APK
        from androguard.core.bytecodes.axml import AXMLPrinter
        ANDROGUARD_OK = True
    except ImportError:
        ANDROGUARD_OK = False

# ------------------------------------------------------------------------------
# CONFIGURATION & DESIGN SYSTEM
# ------------------------------------------------------------------------------
MAPPING_TABLE = [
    {"preuve": "Manifest.xml (Surface d'attaque)", "masvs": "MASVS-PLATFORM-1", "mastg": "MASTG-TEST-0012", "desc": "Verification des composants exportes et configurations IPC."},
    {"preuve": "Permissions extract", "masvs": "MASVS-STORAGE-1", "mastg": "MASTG-TEST-0052", "desc": "Validation du principe de moindre privilege."},
    {"preuve": "Analyse SBOM (.so)", "masvs": "MASVS-CODE-4", "mastg": "MASTG-TEST-0044", "desc": "Verification des bibliotheques tierces non securisees."},
    {"preuve": "Recherche de secrets", "masvs": "MASVS-CRYPTO-1", "mastg": "MASTG-TEST-0015", "desc": "Detection de cles d'API ou mots de passe hardcodes."},
]

class AdvancedApkAnalyzer:
    def __init__(self, apk_path, output_base, log_func):
        self.apk_path = apk_path
        self.apk_name = os.path.basename(apk_path)
        
        # Amelioration Technique : Regrouper tous les rapports dans un sous-dossier
        reports_dir = os.path.join(output_base, "Rapports_Audits")
        os.makedirs(reports_dir, exist_ok=True)
        safe_name = self.apk_name.replace('.apk', '')
        self.output_dir = os.path.join(reports_dir, f"Audit_{safe_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
        
        self.log = log_func
        self.results = {
            "score": 0,
            "score_details": {},
            "manifest_info": {
                "package": "Inconnu",
                "version_code": "Inconnu",
                "version_name": "Inconnu",
                "allow_backup": False,
                "debuggable": False,
                "size_mb": os.path.getsize(apk_path) / (1024 * 1024)
            },
            "permissions": [],
            "exported_components": [],
            "libraries": [],
            "secrets": [],
            "hashes": {},
            "recommendations": [],
            "dynamic_evidence": {"screenshot": False, "logs": False}
        }

    def run(self, progress_callback):
        os.makedirs(self.output_dir, exist_ok=True)
        steps = [
            (self._compute_hashes, "Calcul des empreintes..."),
            (self._extract_manifest, "Analyse du Manifest et composants..."),
            (self._analyze_permissions, "Revue des permissions..."),
            (self._generate_sbom, "Inventaire des dependances..."),
            (self._scan_secrets, "Recherche de secrets et donnees sensibles..."),
            (self._capture_device_evidence, "Capture des Logs et Screenshots (via ADB)..."),
            (self._compute_score, "Calcul du score de risque contextuel..."),
            (self._generate_ia_summary, "Generation du controle de coherence IA..."),
            (self._generate_final_reports, "Generation des rapports finaux...")
        ]
        
        for i, (func, msg) in enumerate(steps):
            self.log(f"[*] {msg}")
            func()
            progress_callback((i + 1) * 100 // len(steps))
            
        self.log(f"[+] Audit termine. Rapport disponible dans : {self.output_dir}")
        return self.output_dir

    def _compute_hashes(self):
        sha256 = hashlib.sha256()
        with open(self.apk_path, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                sha256.update(block)
        self.results["hashes"]["sha256"] = sha256.hexdigest()
        
        with open(os.path.join(self.output_dir, "apk_hash.txt"), "w") as f:
            f.write(f"SHA-256: {self.results['hashes']['sha256']}\n")

    def _extract_manifest(self):
        manifest_path = os.path.join(self.output_dir, "AndroidManifest.xml")
        xml_content_str = None
        
        # 1. Utilisation d'ANDROGUARD pour parser le manifest comme demande
        if ANDROGUARD_OK:
            try:
                apk = APK(self.apk_path)
                xml_content = apk.get_android_manifest_axml().get_xml()
                if isinstance(xml_content, bytes):
                    xml_content_str = xml_content.decode('utf-8', errors='ignore')
                else:
                    xml_content_str = xml_content
            except Exception as e:
                self.log(f"[-] Parsing complet echoue, tentative AXML direct... ({e})")
                try:
                    with zipfile.ZipFile(self.apk_path, 'r') as z:
                        xml_bytes = z.read('AndroidManifest.xml')
                        printer = AXMLPrinter(xml_bytes)
                        xml_content = printer.get_xml()
                        if isinstance(xml_content, bytes):
                            xml_content_str = xml_content.decode('utf-8', errors='ignore')
                        else:
                            xml_content_str = xml_content
                except Exception as e2:
                    self.log(f"[!] Erreur critique Manifest: {e2}")

        if xml_content_str:
            with open(manifest_path, "w", encoding='utf-8') as f:
                f.write(xml_content_str)
            
            import xml.etree.ElementTree as ET
            try:
                root = ET.fromstring(xml_content_str)
                ns = {'android': 'http://schemas.android.com/apk/res/android'}
                self.results["manifest_info"]["package"] = root.get("package", "Inconnu")
                self.results["manifest_info"]["version_code"] = root.get("{http://schemas.android.com/apk/res/android}versionCode", "Inconnu")
                self.results["manifest_info"]["version_name"] = root.get("{http://schemas.android.com/apk/res/android}versionName", "Inconnu")
                
                application = root.find("application")
                if application is not None:
                    allow_backup = application.get("{http://schemas.android.com/apk/res/android}allowBackup")
                    if allow_backup and allow_backup.lower() == "true":
                        self.results["manifest_info"]["allow_backup"] = True
                        
                    # Ajout de l'extraction debuggable
                    debuggable = application.get("{http://schemas.android.com/apk/res/android}debuggable")
                    if debuggable and debuggable.lower() == "true":
                        self.results["manifest_info"]["debuggable"] = True
                
                components = []
                for comp_type in ["activity", "service", "receiver", "provider"]:
                    for comp in root.findall(f".//{{*}}{comp_type}"):
                        name = comp.get("{http://schemas.android.com/apk/res/android}name", "Inconnu")
                        exported = comp.get("{http://schemas.android.com/apk/res/android}exported")
                        
                        is_exported = False
                        if exported and exported.lower() == "true":
                            is_exported = True
                        elif exported is None and comp.find("{*}intent-filter") is not None:
                            is_exported = True
                            
                        if is_exported:
                            perm = comp.get("{http://schemas.android.com/apk/res/android}permission", "Aucune")
                            components.append({"nom": name, "type": comp_type.capitalize(), "exporte": "Oui", "permission": perm})
                
                self.results["exported_components"] = components

            except Exception as e:
                self.log(f"[!] Erreur de parsing ElementTree: {e}")
        else:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                if 'AndroidManifest.xml' in z.namelist():
                    z.extract('AndroidManifest.xml', self.output_dir)

    def _analyze_permissions(self):
        perms = []
        manifest_path = os.path.join(self.output_dir, "AndroidManifest.xml")
        
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    
                matches = re.findall(r'<uses-permission[^>]+name="([^"]+)"', content)
                for p in set(matches):
                    level = "Normal"
                    if "signature" in p.lower() or "system" in p.lower():
                        level = "Signature/System"
                    elif any(danger in p for danger in ["INTERNET", "STORAGE", "LOCATION", "CAMERA", "CONTACTS", "SMS"]):
                        level = "Dangerous"
                    perms.append({"nom": p, "niveau": level, "justification": "A valider manuellement"})
            except Exception as e:
                self.log(f"[!] Erreur permissions: {e}")
                
        self.results["permissions"] = perms

    def _generate_sbom(self):
        # CORRECTION 1: Utilisation d'un set() pour supprimer les doublons de bibliotheques natives
        libraries_set = set()
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                for name in z.namelist():
                    if name.endswith('.so'):
                        libraries_set.add(os.path.basename(name))
        except: pass
        
        self.results["libraries"] = [
            {"nom": lib, "version": "Inconnue", "vulns": "Verifier NVD/CVE manuellement"}
            for lib in libraries_set
        ]

    def _scan_secrets(self):
        secrets_found = []
        # CORRECTION 2: Renforcement des patterns de detection de secrets
        patterns = {
            "Email": r'[\w\.-]+@[\w\.-]+\.\w+',
            "IP_Address": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            "API_Key": r"[A-Za-z0-9]{32,}",
            "Password": r"password\s*=\s*[\"']([^\"']+)[\"']",
            "Token": r"token\s*=\s*[\"']([^\"']+)[\"']",
            "JWT": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
        }
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                for name in z.namelist():
                    if name.endswith(('.xml', '.json', '.txt', '.properties', '.js', '.html')):
                        try:
                            content = z.read(name).decode('utf-8', errors='ignore')
                            for s_type, regex in patterns.items():
                                for match in re.findall(regex, content, re.IGNORECASE):
                                    if isinstance(match, tuple):
                                        match = match[0]
                                    
                                    # Filtres anti-faux positifs de base
                                    if s_type == "IP_Address" and match in ["127.0.0.1", "0.0.0.0", "255.255.255.255", "1.0.0.0"]:
                                        continue
                                    if s_type == "Email" and match.endswith(("example.com", "android.com")):
                                        continue
                                    if s_type == "API_Key":
                                        if name.startswith(("res/layout", "res/color", "res/drawable", "res/anim")):
                                            continue
                                        if not (any(c.islower() for c in match) and any(c.isupper() for c in match) and any(c.isdigit() for c in match)):
                                            continue
                                            
                                    hashed_val = hashlib.md5(match.encode()).hexdigest()[:8]
                                    secrets_found.append({
                                        "type": s_type,
                                        "localisation": name,
                                        "valeur_anonymisee": f"REDACTED_{hashed_val}"
                                    })
                        except: continue
        except: pass
        
        self.results["secrets"] = secrets_found
        # Generation explicite de secrets_detected.json
        with open(os.path.join(self.output_dir, "secrets_detected.json"), "w", encoding="utf-8") as f:
            json.dump({"secrets_detectes": secrets_found}, f, indent=4)

    def _capture_device_evidence(self):
        import subprocess
        
        try:
            res = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=5)
            if "device\n" not in res.stdout:
                self.log("[-] Aucun appareil ADB detecte. Ignorer screenshots et logs.")
                return
                
            self.log("[*] Appareil detecte. Capture d'ecran en cours...")
            subprocess.run(["adb", "shell", "screencap", "-p", "/sdcard/audit_screen.png"], timeout=10)
            screen_path = os.path.join(self.output_dir, "screenshot_ui.png")
            subprocess.run(["adb", "pull", "/sdcard/audit_screen.png", screen_path], timeout=10)
            subprocess.run(["adb", "shell", "rm", "/sdcard/audit_screen.png"], timeout=5)
            if os.path.exists(screen_path):
                self.results["dynamic_evidence"]["screenshot"] = True
                
            self.log("[*] Extraction des logs systeme (Logcat)...")
            log_res = subprocess.run(["adb", "logcat", "-d"], capture_output=True, text=True, timeout=15)
            raw_logs = log_res.stdout
            
            anon_logs = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP_REDACTED]', raw_logs)
            anon_logs = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '[EMAIL_REDACTED]', anon_logs)
            
            lines = anon_logs.split('\n')[-500:]
            with open(os.path.join(self.output_dir, "logs_anonymises.txt"), "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            self.results["dynamic_evidence"]["logs"] = True
            
            subprocess.run(["adb", "logcat", "-c"], timeout=5)
        except Exception as e:
            self.log(f"[-] Erreur capture ADB: {e}")

    def _compute_score(self):
        # CORRECTION 4: Calcul du score detaille par point
        score = 0
        recs = []
        details = {
            "composants_exportes_pts": 0,
            "allow_backup_pts": 0,
            "debuggable_pts": 0,
            "permissions_dangereuses_pts": 0,
            "secrets_pts": 0,
        }
        
        # Permissions dangereuses (+5 par permission)
        nb_dangerous = sum(1 for p in self.results["permissions"] if p["niveau"] == "Dangerous")
        if nb_dangerous > 0:
            details["permissions_dangereuses_pts"] = nb_dangerous * 5
            score += details["permissions_dangereuses_pts"]
            recs.append(f"Retirer ou justifier les {nb_dangerous} permissions dangereuses.")
            
        # Composants exportes sans restriction (+10 par composant)
        nb_exported_no_perm = sum(1 for c in self.results["exported_components"] if c["permission"] == "Aucune" and c["exporte"] == "Oui")
        if nb_exported_no_perm > 0:
            details["composants_exportes_pts"] = nb_exported_no_perm * 10
            score += details["composants_exportes_pts"]
            recs.append(f"Proteger les {nb_exported_no_perm} composants exportes sans restriction via une permission.")

        # Secrets detectes (+15 par secret)
        nb_secrets = len(self.results["secrets"])
        if nb_secrets > 0:
            details["secrets_pts"] = nb_secrets * 15
            score += details["secrets_pts"]
            recs.append(f"Purger les {nb_secrets} secrets hardcodes du code source (Utiliser un KeyStore).")
            
        # allowBackup (+10)
        if self.results["manifest_info"].get("allow_backup"):
            details["allow_backup_pts"] = 10
            score += 10
            recs.append("Definir android:allowBackup='false' pour eviter l'extraction de donnees.")
            
        # debuggable (+10)
        if self.results["manifest_info"].get("debuggable"):
            details["debuggable_pts"] = 10
            score += 10
            recs.append("Definir android:debuggable='false' en production.")

        self.results["score_details"] = details
        self.results["score"] = min(score, 100)
        self.results["recommendations"] = recs

    def _generate_ia_summary(self):
        # CORRECTION 3: Fichier IA formaté exactement selon la consigne stricte
        
        is_adb_connected = self.results["dynamic_evidence"].get("screenshot") or self.results["dynamic_evidence"].get("logs")
        adb_msg = "L'audit est complet. Toutes les preuves ont ete collectees." if is_adb_connected else "L'audit est partiel. Les preuves dynamiques sont absentes car aucun appareil ADB n'a ete detecte."
        
        recs_text = ""
        # On recupere jusqu'a 3 recommandations maximum
        safe_recs = self.results["recommendations"] + ["Aucune autre recommandation", "Aucune autre recommandation", "Aucune autre recommandation"]
        for i in range(3):
            recs_text += f"{i+1}. {safe_recs[i]}\n"
            
        summary = f"""=== SYNTHESE IA - EVIDENCE COLLECTOR PRO ===
Application: {self.apk_name}
Date: {datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")}
Score de risque: {self.results['score']}/100

PREUVES COLLECTEES:
- Hash SHA256: {'OK' if self.results['hashes'].get('sha256') else 'MISSING'}
- Manifest XML: {'OK' if os.path.exists(os.path.join(self.output_dir, 'AndroidManifest.xml')) else 'MISSING'}
- Permissions: {'OK' if self.results['permissions'] else 'MISSING'} ({len(self.results['permissions'])} permissions)
- SBOM: {'OK' if self.results['libraries'] else 'MISSING'} ({len(self.results['libraries'])} librairies)
- Secrets: {'OK' if self.results['secrets'] else 'MISSING'} ({len(self.results['secrets'])} secrets trouves)
- Screenshots: {'OK' if self.results['dynamic_evidence'].get('screenshot') else 'MISSING'}
- Logs anonymises: {'OK' if self.results['dynamic_evidence'].get('logs') else 'MISSING'}

CONTROLE DE COHERENCE:
{adb_msg}

RECOMMANDATIONS PRIORITAIRES:
{recs_text}"""
        
        with open(os.path.join(self.output_dir, "ia_coherence_summary.txt"), "w", encoding="utf-8") as f:
            f.write(summary)

    def _generate_final_reports(self):
        # CORRECTION 5: HTML sans emoji et ajout de la section DETAILS DU SCORE
        
        html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport d'Audit - {self.apk_name}</title>
    <style>
        body {{ font-family: Arial, Helvetica, sans-serif; background-color: #FFFFFF; color: #333333; margin: 0; padding: 0; line-height: 1.5; }}
        .header {{ background-color: #FF6B00; color: #FFFFFF; padding: 30px 40px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 28px; font-weight: normal; text-transform: uppercase; letter-spacing: 1px; }}
        .header p {{ margin: 10px 0 0 0; font-size: 14px; opacity: 0.9; }}
        
        .container {{ max-width: 900px; margin: 0 auto; padding: 40px 20px; }}
        
        .dashboard {{ display: flex; justify-content: space-between; border: 1px solid #EEEEEE; margin-bottom: 30px; }}
        .dash-box {{ padding: 20px; text-align: center; flex: 1; border-right: 1px solid #EEEEEE; }}
        .dash-box:last-child {{ border-right: none; }}
        .dash-value {{ font-size: 24px; font-weight: bold; color: #FF6B00; display: block; margin-bottom: 5px; }}
        .dash-label {{ font-size: 12px; color: #666666; text-transform: uppercase; }}
        
        h2 {{ color: #FF6B00; font-size: 16px; text-transform: uppercase; border-bottom: 1px solid #EEEEEE; padding-bottom: 10px; margin-top: 40px; }}
        
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #EEEEEE; }}
        th {{ color: #FF6B00; font-weight: bold; border-bottom: 2px solid #FF6B00; background-color: #FFFFFF; text-transform: uppercase; font-size: 11px; }}
        tr:nth-child(even) {{ background-color: #F8F9FA; }}
        
        ul.recommendations {{ list-style-type: none; padding: 0; }}
        ul.recommendations li {{ padding: 10px 15px; border-left: 3px solid #FF6B00; background-color: #F8F9FA; margin-bottom: 10px; font-size: 14px; }}
        
        .footer {{ text-align: center; padding: 30px; font-size: 12px; color: #999999; border-top: 1px solid #EEEEEE; margin-top: 50px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Rapport d'Audit de Securite</h1>
        <p>{self.apk_name} | {datetime.datetime.now().strftime("%d/%m/%Y")}</p>
    </div>

    <div class="container">
        
        <div class="dashboard">
            <div class="dash-box">
                <span class="dash-value">{self.results['score']}/100</span>
                <span class="dash-label">Score de Risque</span>
            </div>
            <div class="dash-box">
                <span class="dash-value">{len(self.results['permissions'])}</span>
                <span class="dash-label">Permissions</span>
            </div>
            <div class="dash-box">
                <span class="dash-value">{len(self.results['exported_components'])}</span>
                <span class="dash-label">Composants Exposes</span>
            </div>
            <div class="dash-box">
                <span class="dash-value">{len(self.results['secrets'])}</span>
                <span class="dash-label">Secrets Detectes</span>
            </div>
        </div>

        <h2>Identite de l'Application</h2>
        <table>
            <tr><th style="width: 30%;">Propriete</th><th>Valeur</th></tr>
            <tr><td>Nom du fichier</td><td>{self.apk_name}</td></tr>
            <tr><td>Package</td><td>{self.results['manifest_info']['package']}</td></tr>
            <tr><td>Version Code</td><td>{self.results['manifest_info']['version_code']}</td></tr>
            <tr><td>Version Name</td><td>{self.results['manifest_info']['version_name']}</td></tr>
            <tr><td>Hash SHA256</td><td><span style="font-family: monospace; font-size: 12px;">{self.results['hashes'].get('sha256', 'N/A')}</span></td></tr>
            <tr><td>Taille</td><td>{self.results['manifest_info']['size_mb']:.2f} MB</td></tr>
            <tr><td>Sauvegarde autorisee (allowBackup)</td><td>{'Oui' if self.results['manifest_info'].get('allow_backup') else 'Non'}</td></tr>
        </table>

        <h2>DETAIL DU CALCUL DU SCORE</h2>
        <table>
            <tr><th style="width: 70%;">Critere</th><th>Points Appliques</th></tr>
            <tr><td>Composants exportes sans permission</td><td>+{self.results['score_details']['composants_exportes_pts']} points</td></tr>
            <tr><td>allowBackup=true</td><td>+{self.results['score_details']['allow_backup_pts']} points</td></tr>
            <tr><td>debuggable=true</td><td>+{self.results['score_details']['debuggable_pts']} points</td></tr>
            <tr><td>Permissions dangereuses</td><td>+{self.results['score_details']['permissions_dangereuses_pts']} points</td></tr>
            <tr><td>Secrets detectes</td><td>+{self.results['score_details']['secrets_pts']} points</td></tr>
            <tr style="background-color: #f1f1f1; font-weight: bold;"><td style="text-align: right;">TOTAL DU RISQUE</td><td>{self.results['score']}/100</td></tr>
        </table>

        <h2>NIVEAU DE RISQUE</h2>
        <table>
            <tr><th>Plage de score</th><th>Niveau de Risque</th></tr>
            <tr><td>0-20</td><td>Faible</td></tr>
            <tr><td>21-50</td><td>Moyen</td></tr>
            <tr><td>51-80</td><td>Eleve</td></tr>
            <tr><td>81-100</td><td>Critique</td></tr>
        </table>

        <h2>Recommandations de Securite</h2>
        <ul class="recommendations">
            {"".join(f"<li>{r}</li>" for r in self.results['recommendations']) if self.results['recommendations'] else "<li>Aucune recommandation critique.</li>"}
        </ul>

        <h2>Permissions Declarees</h2>
        <table>
            <thead><tr><th>Permission</th><th>Niveau de protection</th><th>Justification</th></tr></thead>
            <tbody>
                {"".join(f"<tr><td><span style='font-family: monospace;'>{p['nom']}</span></td><td>{p['niveau']}</td><td>{p['justification']}</td></tr>" for p in self.results['permissions']) if self.results['permissions'] else "<tr><td colspan='3'>Aucune permission detectee</td></tr>"}
            </tbody>
        </table>

        <h2>Composants Exportes (Surface d'Attaque)</h2>
        <table>
            <thead><tr><th>Composant</th><th>Type</th><th>Exporte</th><th>Permission requise</th></tr></thead>
            <tbody>
                {"".join(f"<tr><td><span style='font-family: monospace;'>{c['nom']}</span></td><td>{c['type']}</td><td>{c['exporte']}</td><td>{c['permission']}</td></tr>" for c in self.results['exported_components']) if self.results['exported_components'] else "<tr><td colspan='4'>Aucun composant expose detecte</td></tr>"}
            </tbody>
        </table>

        <h2>Secrets et Donnees Sensibles</h2>
        <table>
            <thead><tr><th>Type</th><th>Localisation</th><th>Valeur Anonymisee</th></tr></thead>
            <tbody>
                {"".join(f"<tr><td>{s['type']}</td><td><span style='font-family: monospace;'>{s['localisation']}</span></td><td><span style='font-family: monospace;'>{s['valeur_anonymisee']}</span></td></tr>" for s in self.results['secrets']) if self.results['secrets'] else "<tr><td colspan='3'>Aucun secret detecte</td></tr>"}
            </tbody>
        </table>

        <h2>Dependances (SBOM)</h2>
        <table>
            <thead><tr><th>Bibliotheque Native</th><th>Version</th><th>Vulnerabilites Connues</th></tr></thead>
            <tbody>
                {"".join(f"<tr><td><span style='font-family: monospace;'>{l['nom']}</span></td><td>{l['version']}</td><td>{l['vulns']}</td></tr>" for l in self.results['libraries']) if self.results['libraries'] else "<tr><td colspan='3'>Aucune bibliotheque native detectee</td></tr>"}
            </tbody>
        </table>

        <h2>Conformite MASVS & MASTG</h2>
        <table>
            <thead><tr><th>Preuve Collectee</th><th>Exigence MASVS</th><th>Test MASTG</th><th>Description</th></tr></thead>
            <tbody>
                {"".join(f"<tr><td>{m['preuve']}</td><td><strong>{m['masvs']}</strong></td><td><strong>{m['mastg']}</strong></td><td>{m['desc']}</td></tr>" for m in MAPPING_TABLE)}
            </tbody>
        </table>
        
    </div>
    
    <div class="footer">
        Genere par Evidence Collector Pro - Outil d'audit automatise
    </div>
</body>
</html>"""
        with open(os.path.join(self.output_dir, "index.html"), "w", encoding="utf-8") as f:
            f.write(html_content)

# ------------------------------------------------------------------------------
# GUI - INTERFACE UTILISATEUR
# ------------------------------------------------------------------------------
class AppGui:
    def __init__(self, root):
        self.root = root
        self.root.title("Evidence Collector Pro")
        self.root.geometry("700x550")
        self.root.configure(bg="#FFFFFF")
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TButton", padding=6, relief="flat", background="#FF6B00", foreground="#FFFFFF", font=("Arial", 10, "bold"))
        style.map("TButton", background=[('active', '#E65C00')])
        
        # Header
        header_frame = tk.Frame(root, bg="#FF6B00", height=80)
        header_frame.pack(fill=tk.X, side=tk.TOP)
        header_frame.pack_propagate(False)
        tk.Label(header_frame, text="EVIDENCE COLLECTOR PRO", bg="#FF6B00", fg="#FFFFFF", font=("Arial", 16, "bold")).pack(pady=15)
        tk.Label(header_frame, text="Analyse Statique et Preuves d'Audit", bg="#FF6B00", fg="#FFFFFF", font=("Arial", 10)).pack()

        # Main container
        main_frame = tk.Frame(root, bg="#FFFFFF", padx=30, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # File Selection
        file_frame = tk.Frame(main_frame, bg="#FFFFFF")
        file_frame.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(file_frame, text="Fichier APK a analyser :", bg="#FFFFFF", font=("Arial", 10, "bold"), fg="#333333").pack(anchor="w")
        
        self.path_var = tk.StringVar()
        entry = tk.Entry(file_frame, textvariable=self.path_var, font=("Arial", 10), bg="#F8F9FA", relief="solid", bd=1)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5, padx=(0, 10))
        
        ttk.Button(file_frame, text="Parcourir", command=self.browse_file).pack(side=tk.RIGHT)

        # Progress
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress.pack(fill=tk.X, pady=(10, 5))

        # Logs
        tk.Label(main_frame, text="Console d'execution :", bg="#FFFFFF", font=("Arial", 10, "bold"), fg="#333333").pack(anchor="w")
        self.log_area = tk.Text(main_frame, height=12, bg="#333333", fg="#FFFFFF", font=("Courier", 9), relief="flat")
        self.log_area.pack(fill=tk.BOTH, expand=True, pady=(5, 20))

        # Actions
        action_frame = tk.Frame(main_frame, bg="#FFFFFF")
        action_frame.pack(fill=tk.X)
        
        self.run_btn = ttk.Button(action_frame, text="Lancer l'Audit", command=self.start_audit)
        self.run_btn.pack(side=tk.LEFT)
        
        self.report_btn = ttk.Button(action_frame, text="Ouvrir le Rapport", command=self.open_report, state=tk.DISABLED)
        self.report_btn.pack(side=tk.RIGHT)
        
        self.last_report_dir = None

    def browse_file(self):
        filepath = filedialog.askopenfilename(filetypes=[("Android APK", "*.apk")])
        if filepath:
            self.path_var.set(filepath)

    def log(self, message):
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)
        self.root.update_idletasks()

    def update_progress(self, val):
        self.progress_var.set(val)
        self.root.update_idletasks()

    def start_audit(self):
        apk_path = self.path_var.get()
        if not os.path.exists(apk_path):
            messagebox.showerror("Erreur", "Fichier APK introuvable.")
            return
            
        self.run_btn.config(state=tk.DISABLED)
        self.report_btn.config(state=tk.DISABLED)
        self.progress_var.set(0)
        self.log_area.delete(1.0, tk.END)
        self.log("=== Demarrage de l'Audit ===")
        
        def run_thread():
            try:
                base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
                analyzer = AdvancedApkAnalyzer(apk_path, base_dir, self.log)
                report_dir = analyzer.run(self.update_progress)
                self.last_report_dir = report_dir
                self.root.after(0, lambda: self.report_btn.config(state=tk.NORMAL))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Erreur", str(e)))
            finally:
                self.root.after(0, lambda: self.run_btn.config(state=tk.NORMAL))
                
        threading.Thread(target=run_thread, daemon=True).start()

    def open_report(self):
        if self.last_report_dir:
            os.startfile(self.last_report_dir)

if __name__ == "__main__":
    root = tk.Tk()
    app = AppGui(root)
    root.mainloop()
