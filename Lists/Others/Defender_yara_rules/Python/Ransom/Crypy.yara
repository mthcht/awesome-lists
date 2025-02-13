rule Ransom_Python_Crypy_A_2147717786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Python/Crypy.A"
        threat_id = "2147717786"
        type = "Ransom"
        platform = "Python: Python scripts"
        family = "Crypy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {76 69 63 74 69 6d 2e 70 68 70 3f 69 6e 66 6f 3d 73 04 00 00 00 26 69 70 3d 74 04 00 00 00 78 5f 49 44 74 05 00 00 00 78 5f 55 44 50 74 05 00}  //weight: 1, accuracy: High
        $x_1_2 = {65 6e 63 72 79 70 74 6f 72 2e 70 79 77 74 0d 00 00 00 64 65 6c 65 74 65 5f 73 68 61 64 6f 77}  //weight: 1, accuracy: High
        $x_1_3 = {65 6e 63 72 79 70 74 5f 66 69 6c 65 28 05 00 00 00 52 19 00 00 00 74 09 00 00 00 63 6f 6e 66 69 67 75 72 6c 74 0b 00 00 00 67 6c 6f 62 5f 63 6f 6e 66 69 67 74 03 00 00 00 6b 65 79 74 0b 00 00 00 6e 65 77 66 69 6c 65 6e 61 6d 65}  //weight: 1, accuracy: High
        $x_1_4 = {76 69 63 74 69 6d 28 03 00 00 00 74 03 00 00 00 64 69 72 74 03 00 00 00 65 78 74 74 05 00 00 00 66 69 6c 65 73 28 00 00 00 00 28 00 00 00 00 73 0d 00 00 00 65 6e 63 72 79 70 74 6f 72 2e 70 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Python_Crypy_A_2147717786_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Python/Crypy.A"
        threat_id = "2147717786"
        type = "Ransom"
        platform = "Python: Python scripts"
        family = "Crypy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bcdedit /set {default} bootstatuspolicy ignoreallfailuresss" ascii //weight: 1
        $x_1_2 = "REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /t REG_DWORD /v DisableRegistryTools /d 1" ascii //weight: 1
        $x_1_3 = "REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /t REG_DWORD /v DisableTaskMgr /d 1" ascii //weight: 1
        $x_1_4 = "REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /t REG_DWORD /v DisableCMD /d 1" ascii //weight: 1
        $x_1_5 = "REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoRun /d 1" ascii //weight: 1
        $x_1_6 = "Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_7 = "Win_encryptor.pyw" ascii //weight: 1
        $x_1_8 = "REG ADD HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server /v fDenyTSConnections /t REG_DWORD /d 0" ascii //weight: 1
        $x_1_9 = "create_remote_desktop." ascii //weight: 1
        $x_1_10 = "_README_FOR_DECRYPT.t" ascii //weight: 1
        $x_1_11 = "! ! ! W AR N I N G ! ! !" ascii //weight: 1
        $x_1_12 = "All your files are encrypted by" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

