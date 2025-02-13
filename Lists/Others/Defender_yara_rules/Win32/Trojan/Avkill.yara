rule Trojan_Win32_Avkill_E_2147637568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Avkill.E"
        threat_id = "2147637568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Avkill"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Interner Settings\\Zones\\3\\1803" ascii //weight: 1
        $x_1_2 = "taskkill /f /im VsTskMgr.exe" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\360Safe\\safemon\\ExecAccess" ascii //weight: 1
        $x_1_4 = "[HKEY_CLASSES_ROOT\\exefile\\DefaultIcon]" ascii //weight: 1
        $x_1_5 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 52 61 76 2e 65 78 65 00 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 52 61 76 6d 6f 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Avkill_S_2147655155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Avkill.S"
        threat_id = "2147655155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Avkill"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 6a 63 74 36 00 50 72 6f 6a 65 63 74 31 00 00 50 72 6f 6a 65 63 74 31}  //weight: 1, accuracy: High
        $x_1_2 = "pjct6x\\Project1.vbp" wide //weight: 1
        $x_1_3 = "KeServiceDescriptorTable" wide //weight: 1
        $x_1_4 = {15 00 00 00 5a 77 53 79 73 74 65 6d 44 65 62 75 67 43 6f 6e 74 72 6f 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Avkill_A_2147686478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Avkill.gen!A"
        threat_id = "2147686478"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Avkill"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "220"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {63 00 63 00 73 00 76 00 63 00 68 00 73 00 74 00 2e 00 65 00 78 00 65 00 2e 00 6d 00 61 00 6e 00 69 00 66 00 65 00 73 00 74 00 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {61 00 76 00 70 00 2e 00 65 00 78 00 65 00 2e 00 6d 00 61 00 6e 00 69 00 66 00 65 00 73 00 74 00 00 00}  //weight: 10, accuracy: High
        $x_10_3 = {73 00 61 00 66 00 65 00 6d 00 6f 00 6e 00 5c 00 33 00 36 00 30 00 54 00 72 00 61 00 79 00 2e 00 65 00 78 00 65 00 2e 00 63 00 6f 00 6e 00 66 00 69 00 67 00 00 00}  //weight: 10, accuracy: High
        $x_10_4 = {70 00 73 00 70 00 72 00 6f 00 74 00 65 00 67 00 65 00 2e 00 65 00 78 00 65 00 2e 00 6d 00 61 00 6e 00 69 00 66 00 65 00 73 00 74 00 00 00}  //weight: 10, accuracy: High
        $x_10_5 = {6d 73 73 65 63 65 73 2e 65 78 65 00 4d 53 41 53 43 75 69 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_100_6 = {53 65 43 72 65 61 74 65 50 61 67 65 66 69 6c 65 50 72 69 76 69 6c 65 67 65 00}  //weight: 100, accuracy: High
        $x_100_7 = {4e 74 43 72 65 61 74 65 50 61 67 69 6e 67 46 69 6c 65 00}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Avkill_B_2147686479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Avkill.gen!B"
        threat_id = "2147686479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Avkill"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 61 66 65 72 5c 43 6f 64 65 49 64 65 6e 74 69 66 69 65 72 73 5c 30 5c 50 61 74 68 73 5c 00}  //weight: 10, accuracy: High
        $x_10_2 = {53 61 66 65 72 46 6c 61 67 73 00 [0-10] 49 74 65 6d 44 61 74 61 00}  //weight: 10, accuracy: Low
        $x_10_3 = {44 65 66 61 75 6c 74 4c 65 76 65 6c 00 [0-10] 54 72 61 6e 73 70 61 72 65 6e 74 45 6e 61 62 6c 65 64 00}  //weight: 10, accuracy: Low
        $x_10_4 = {50 6f 6c 69 63 79 53 63 6f 70 65 00 [0-10] 45 78 65 63 75 74 61 62 6c 65 54 79 70 65 73 00}  //weight: 10, accuracy: Low
        $x_50_5 = {4d 69 63 72 6f 73 6f 66 74 20 53 65 63 75 72 69 74 79 20 43 6c 69 65 6e 74 00}  //weight: 50, accuracy: High
        $x_50_6 = {4d 69 63 72 6f 73 6f 66 74 20 53 65 63 75 72 69 74 79 20 45 73 73 65 6e 74 69 61 6c 73 00}  //weight: 50, accuracy: High
        $x_50_7 = {4e 6f 72 74 6f 6e 20 41 6e 74 69 56 69 72 75 73 00}  //weight: 50, accuracy: High
        $x_50_8 = {42 69 74 44 65 66 65 6e 64 65 72 00}  //weight: 50, accuracy: High
        $x_50_9 = {4b 61 73 70 65 72 73 6b 79 20 4c 61 62 00}  //weight: 50, accuracy: High
        $x_50_10 = {41 56 41 53 54 20 53 6f 66 74 77 61 72 65 00}  //weight: 50, accuracy: High
        $x_50_11 = {50 61 6e 64 61 20 53 65 63 75 72 69 74 79 00}  //weight: 50, accuracy: High
        $x_50_12 = {4d 63 41 66 65 65 00}  //weight: 50, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_10_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

