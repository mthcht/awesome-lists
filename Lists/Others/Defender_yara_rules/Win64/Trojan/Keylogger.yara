rule Trojan_Win64_Keylogger_BH_2147844444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Keylogger.BH!MTB"
        threat_id = "2147844444"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[BACKSPACE]" ascii //weight: 1
        $x_1_2 = "[ENTER]" ascii //weight: 1
        $x_1_3 = "[PG UP]" ascii //weight: 1
        $x_1_4 = "[PG DN]" ascii //weight: 1
        $x_1_5 = "[HOME]" ascii //weight: 1
        $x_1_6 = "[RIGHT]" ascii //weight: 1
        $x_1_7 = "[DOWN]" ascii //weight: 1
        $x_1_8 = "[PRINT]" ascii //weight: 1
        $x_1_9 = "[PRT SC]" ascii //weight: 1
        $x_1_10 = "[INSERT]" ascii //weight: 1
        $x_1_11 = "[DELETE]" ascii //weight: 1
        $x_1_12 = "[WIN KEY]" ascii //weight: 1
        $x_1_13 = "[CTRL]" ascii //weight: 1
        $x_1_14 = "Hook procedure has been installed successfully" ascii //weight: 1
        $x_1_15 = "Keylogger is up and running" ascii //weight: 1
        $x_1_16 = "Cannot uninstall the hook procedure" ascii //weight: 1
        $x_1_17 = "Hook procedure has been uninstalled successfully" ascii //weight: 1
        $x_1_18 = "Downloads\\mals\\winkl\\keylogger\\src\\Keylogger\\x64\\Release\\Keylogger.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Keylogger_RR_2147895939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Keylogger.RR!MTB"
        threat_id = "2147895939"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AFDK\\AFDK\\x64\\Release\\AFDK.pdb" ascii //weight: 2
        $x_1_2 = "3301Kira" ascii //weight: 1
        $x_5_3 = "Software\\def9b6cd3f2b0c43097dfbc918862b82" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Keylogger_RB_2147896980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Keylogger.RB!MTB"
        threat_id = "2147896980"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "3301Kira" ascii //weight: 5
        $x_5_2 = "Software\\def9b6cd3f2b0c43097dfbc918862b82" wide //weight: 5
        $x_1_3 = "keylogger save OK" wide //weight: 1
        $x_1_4 = "Keylogger is up and running" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Keylogger_MK_2147959700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Keylogger.MK!MTB"
        threat_id = "2147959700"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_25_1 = {48 8b 85 e8 14 00 00 8b 40 04 c1 e0 10 89 85 e4 14 00 00 48 8b 85 e8 14 00 00 8b 40 08 c1 e0 18 01 85 e4 14}  //weight: 25, accuracy: High
        $x_5_2 = "Keylogger is up and running..." ascii //weight: 5
        $x_5_3 = "Hook procedure has been installed successfully" ascii //weight: 5
        $x_3_4 = "[WIN KEY]" ascii //weight: 3
        $x_2_5 = "[PRT SC]" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_25_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_25_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Keylogger_ARR_2147961378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Keylogger.ARR!MTB"
        threat_id = "2147961378"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Stealth Keylogger Started (Fixed Version)" ascii //weight: 10
        $x_7_2 = "BROESERCOOKIE.exe" ascii //weight: 7
        $x_2_3 = "Payload execution phase completed" ascii //weight: 2
        $x_1_4 = "Browser Cookie Stealer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Keylogger_BMD_2147962966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Keylogger.BMD!MTB"
        threat_id = "2147962966"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\per_main_25\\MicrosoftMigration\\handycafeInstaller\\brserver\\x64\\Release\\KY.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Keylogger_AB_2147965229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Keylogger.AB!MTB"
        threat_id = "2147965229"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keylogger/1.0" wide //weight: 1
        $x_1_2 = "install keyboard hook!" wide //weight: 1
        $x_1_3 = "install mouse hook!" wide //weight: 1
        $x_1_4 = "Screenshot saved" ascii //weight: 1
        $x_1_5 = "Log data sent successfully" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Keylogger_AB_2147965229_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Keylogger.AB!MTB"
        threat_id = "2147965229"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kenz_mutex" ascii //weight: 1
        $x_1_2 = "C2 thread started." ascii //weight: 1
        $x_1_3 = "Keylogger started." ascii //weight: 1
        $x_1_4 = "netsh advfirewall firewall set rule group=\"remote desktop\" new enable=Yes > nul" ascii //weight: 1
        $x_1_5 = "Check failed: VMware Tools registry key found." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Keylogger_LRD_2147967097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Keylogger.LRD!MTB"
        threat_id = "2147967097"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {c7 45 70 72 61 6c 50 f3 0f 7f 4d 60 c7 45 74 72 6f 63 65 c7 45 78 73 73 6f 72 66 c7 45 7c 5c 30 c7 44 24 30 04 00 00 00 c7 44 24 34 04 00 00 00}  //weight: 20, accuracy: High
        $x_1_2 = "CreateMutexA" ascii //weight: 1
        $x_2_3 = "DuplicateTokenEx" ascii //weight: 2
        $x_3_4 = "CreateProcessAsUserA" ascii //weight: 3
        $x_4_5 = "checkip.amazonaws" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Keylogger_LR_2147968428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Keylogger.LR!MTB"
        threat_id = "2147968428"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {49 8b c2 41 8b d0 0f 1f 44 00 00 80 00 02 48 8d 40 01 48 83 ea 01}  //weight: 20, accuracy: High
        $x_10_2 = {49 ff c0 66 46 39 2c 40 75 ?? 45 03 c0 4c 8b cf 45 85 c0 74 ?? 48 8d 45 e0 41 8b d0 0f 1f 40 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

