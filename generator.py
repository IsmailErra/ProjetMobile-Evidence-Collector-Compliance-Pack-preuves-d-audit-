import sys
import os

def main():
    vuln_type = input("Enter vulnerability type (exported_component/cleartext_traffic/hardcoded_secret/debuggable_enabled): ").strip()
    
    if vuln_type not in ["exported_component", "cleartext_traffic", "hardcoded_secret", "debuggable_enabled"]:
        print("Error: Invalid vulnerability type")
        sys.exit(1)

    test_file = ""
    test_content = ""
    summary = ""
    test_file_no_ext = ""

    if vuln_type == "exported_component":
        pkg = input("Enter package name: ").strip()
        comp = input("Enter component name: ").strip()
        
        test_file = "SecurityRegressionTest.kt"
        test_file_no_ext = "SecurityRegressionTest.kt" # Maintained to fit the template exact structure
        short_comp = comp.split('.')[-1] if '.' in comp else comp
        summary = f"Verifies that {short_comp} is not exported"
        
        test_content = f"""import org.junit.Test
import org.junit.runner.RunWith
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import android.content.Intent
import android.content.pm.PackageManager

@RunWith(AndroidJUnit4::class)
class ExportedComponentSecurityTest {{

    @Test
    fun testComponentNotExposed() {{
        val context = ApplicationProvider.getApplicationContext()
        val packageManager = context.packageManager
        val intent = Intent()
        intent.component = android.content.ComponentName("{pkg}", "{comp}")
        
        val resolveInfo = packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
        assert(resolveInfo == null) {{ "Component {comp} is still exported" }}
    }}
}}"""

    elif vuln_type == "cleartext_traffic":
        test_file = "test_cleartext_traffic.py"
        test_file_no_ext = "test_cleartext_traffic"
        summary = "Verifies that cleartext traffic is disabled"
        
        test_content = """import os
import xml.etree.ElementTree as ET

def test_cleartext_traffic_disabled():
    manifest_path = "app/src/main/AndroidManifest.xml"
    if not os.path.exists(manifest_path):
        manifest_path = "AndroidManifest.xml"
    
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    ns = {'android': 'http://schemas.android.com/apk/res/android'}
    
    uses_cleartext = root.get('{http://schemas.android.com/apk/res/android}usesCleartextTraffic')
    assert uses_cleartext != 'true', "Cleartext traffic is enabled"
    print("CLEARTEXT_TRAFFIC_TEST: PASSED")

if __name__ == "__main__":
    test_cleartext_traffic_disabled()"""

    elif vuln_type == "hardcoded_secret":
        pattern = input("Enter secret pattern: ").strip()
        
        test_file = "test_hardcoded_secret.py"
        test_file_no_ext = "test_hardcoded_secret"
        summary = "Verifies that secret is not hardcoded"
        
        test_content = f"""import os
import re

def test_secret_not_hardcoded():
    secret_pattern = r"{pattern}"
    source_dirs = ["app/src/main/java", "app/src/main/kotlin"]
    
    for directory in source_dirs:
        if not os.path.exists(directory):
            continue
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith(('.java', '.kt')):
                    path = os.path.join(root, file)
                    with open(path, 'r') as f:
                        content = f.read()
                        if re.search(secret_pattern, content):
                            raise AssertionError(f"Secret found in {{path}}")
    print("SECRET_TEST: PASSED")

if __name__ == "__main__":
    test_secret_not_hardcoded()"""

    elif vuln_type == "debuggable_enabled":
        test_file = "test_debuggable_enabled.py"
        test_file_no_ext = "test_debuggable_enabled"
        summary = "Verifies that android:debuggable is false"
        
        test_content = """import xml.etree.ElementTree as ET

def test_debuggable_disabled():
    manifest_path = "app/src/main/AndroidManifest.xml"
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    ns = {'android': 'http://schemas.android.com/apk/res/android'}
    
    debuggable = root.get('{http://schemas.android.com/apk/res/android}debuggable')
    assert debuggable != 'true', "Application is debuggable"
    print("DEBUGGABLE_TEST: PASSED")

if __name__ == "__main__":
    test_debuggable_disabled()"""

    with open(test_file, 'w', encoding='utf-8') as f:
        f.write(test_content)

    gate_content = f"""#!/bin/bash
echo "Running security regression tests..."
python3 {test_file_no_ext}.py
if [ $? -eq 0 ]; then
    echo "Security tests passed"
    exit 0
else
    echo "Security tests failed - build blocked"
    exit 1
fi"""

    with open("security_gate.sh", 'w', encoding='utf-8') as f:
        f.write(gate_content)

    print("\nOutput:")
    print(f"Test generated: {test_file}")
    print(f"Test summary: {summary}")

if __name__ == "__main__":
    main()
