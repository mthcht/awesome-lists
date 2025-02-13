rule Trojan_Win32_Wisp_A_2147631964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wisp.A"
        threat_id = "2147631964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wisp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 74 74 70 73 3a 2f 2f 6e 6f 74 65 73 2e 74 6f 70 69 78 32 31 63 65 6e 74 75 72 79 2e 63 6f 6d 2f 61 73 70 2f 6b 79 73 5f 61 6c 6c 6f 77 5f 67 65 74 2e 61 73 70 3f 6e 61 6d 65 3d 67 65 74 6b 79 73 2e 6b 79 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {2f 61 73 70 2f 6b 79 73 5f 61 6c 6c 6f 77 5f 70 75 74 2e 61 73 70 3f 74 79 70 65 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {54 68 65 20 70 72 6f 63 65 73 73 20 68 61 73 20 62 65 65 6e 20 75 6e 73 75 63 63 65 73 73 66 75 6c 6c 79 20 6b 69 6c 6c 65 64 21 0a 00}  //weight: 1, accuracy: High
        $x_1_4 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 00 6e 6f 74 65 73 00 00 00 77 73 68 69 70 6e 6f 74 65 73 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {66 69 72 65 66 6f 78 2e 65 78 65 00 2d 72 65 6d 6f 76 65 6b 79 73 00 00 2d 69 6e 73 74 61 6c 6c 6b 79 73 00 5c 73 76 63 68 6f 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 00 00 00 00 6f 75 74 6c 6f 6f 6b 2e 65 78 65 00 69 65 78 70 6c 6f 72 65 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Wisp_A_2147631982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wisp.gen!A"
        threat_id = "2147631982"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wisp"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {2f 6b 79 73 5f 61 6c 6c 6f 77 5f 70 75 74 2e 61 73 70 3f 74 79 70 65 3d 00}  //weight: 20, accuracy: High
        $x_20_2 = {54 68 65 20 70 72 6f 63 65 73 73 20 68 61 73 20 62 65 65 6e 20 75 6e 73 75 63 63 65 73 73 66 75 6c 6c 79 20 6b 69 6c 6c 65 64 21 0a 00}  //weight: 20, accuracy: High
        $x_5_3 = {2f 61 73 70 2f 6b 79 73 5f 61 6c 6c 6f 77 5f 67 65 74 2e 61 73 70 3f 6e 61 6d 65 3d 67 65 74 6b 79 73 2e 6b 79 73 00}  //weight: 5, accuracy: High
        $x_5_4 = {2f 6b 79 73 5f 61 6c 6c 6f 77 5f 67 65 74 2e 61 73 70 3f 6e 61 6d 65 3d 67 65 74 6b 79 73 2e 6a 70 67 00}  //weight: 5, accuracy: High
        $x_1_5 = {66 69 72 65 66 6f 78 2e 65 78 65 00 6f 75 74 6c 6f 6f 6b 2e 65 78 65 00 69 65 78 70 6c 6f 72 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {53 68 75 74 64 6f 77 6e 57 69 74 68 6f 75 74 4c 6f 67 6f 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Wisp_B_2147631986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wisp.B"
        threat_id = "2147631986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wisp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 00 6e 6f 74 65 00 00 00 00 77 73 68 69 70 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 69 72 65 66 6f 78 2e 65 78 65 00 2d 72 65 6d 6f 76 65 6b 79 73 00 00 2d 69 6e 73 74 61 6c 6c 6b 79 73 00 5c 73 76 63 68 6f 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 00 00 00 00 6f 75 74 6c 6f 6f 6b 2e 65 78 65 00 69 65 78 70 6c 6f 72 65 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Wisp_B_2147632297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wisp.gen!B"
        threat_id = "2147632297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wisp"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 61 69 6c 75 65 72 20 2e 2e 2e 20 41 63 63 65 73 73 20 69 73 20 44 65 6e 69 65 64 20 21 0a 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 74 6f 70 70 69 6e 67 20 53 65 72 76 69 63 65 20 2e 2e 2e 2e 20 00 00 6e 6f 20 45 78 69 73 74 73 20 21 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {2a 2e 2a 00 25 2d 33 30 73 2d 3e 25 2d 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Wisp_D_2147723812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wisp.D"
        threat_id = "2147723812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wisp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "novostimir.com" ascii //weight: 1
        $x_1_2 = {5f 6e 6f 74 69 66 79 2e 65 78 65 00 66 72 77 6c 5f 73 65 74 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = {64 72 77 65 62 00 00 00 6e 6f 6e 6f 6e 6f}  //weight: 1, accuracy: High
        $x_1_4 = {6f 75 74 6c 6f 6f 6b 2e 65 78 65 00 65 69 70 78 6f 6c 65 72 65 2e 65 78}  //weight: 1, accuracy: High
        $x_1_5 = {69 66 65 72 6f 66 2e 78 78 65 00 00 63 68 72 6f 6d 65 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_6 = "cmd /c \"reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v start /t REG_SZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

