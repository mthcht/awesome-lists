rule Trojan_Win32_Elvdeng_B_2147645569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Elvdeng.B"
        threat_id = "2147645569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Elvdeng"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Program Files\\iedw.ghi" ascii //weight: 1
        $x_1_2 = "C:\\Progra~1\\lvegned\\config.ini" ascii //weight: 1
        $x_1_3 = {63 6f 6e 66 69 67 00 [0-3] 73 74 61 74 69 63 61 6c 75 72 6c 00 [0-3] 63 68 61 6e 6e 65 6c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {73 74 61 74 69 63 61 6c 75 72 6c 00 [0-3] 63 6f 6e 66 69 67 00 [0-3] 63 68 61 6e 6e 65 6c 00}  //weight: 1, accuracy: Low
        $x_1_5 = {3a 5c 70 6c 75 67 69 6e 01 00 2e 02 00 5c 72 65 6c 65 61 73 65 5c 65 78 65 74 77 6f 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Elvdeng_C_2147645570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Elvdeng.C"
        threat_id = "2147645570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Elvdeng"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 04 00 00 8b d8 ff 15 ?? ?? ?? ?? 6a 00 6a 18 8d 54 24 ?? 52 8b f8 6a 00 57 ff d3 57 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\Progra~1\\lvegned\\config.ini" ascii //weight: 1
        $x_1_3 = {6c 6f 6f 70 75 72 6c 00 [0-3] 63 6f 6e 66 69 67 00 [0-3] 73 69 7a 65 00 [0-3] 48 4f 4f 4b 42 57}  //weight: 1, accuracy: Low
        $x_1_4 = {3a 5c 70 6c 75 67 69 6e 01 00 2e 02 00 5c 72 65 6c 65 61 73 65 5c 65 78 65 74 68 72 65 65 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Elvdeng_D_2147645571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Elvdeng.D"
        threat_id = "2147645571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Elvdeng"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 ff 0f 1f 00 ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 ?? 8b 44 24 ?? 6a 04 68 00 10 00 00 83 c0 01 50 6a 00 56 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\Progra~1\\lvegned\\config.ini" ascii //weight: 1
        $x_1_3 = {63 6f 6e 66 69 67 00 [0-3] 6e 61 76 69 67 61 74 65 75 72 6c 00 [0-3] 69 6e 73 74 61 6c 6c 00 [0-3] 44 49 52 45 43 54 4f 52 59}  //weight: 1, accuracy: Low
        $x_1_4 = {3a 5c 70 6c 75 67 69 6e 01 00 2e 02 00 5c 72 65 6c 65 61 73 65 5c 65 78 65 6f 6e 65 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Elvdeng_E_2147645572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Elvdeng.E"
        threat_id = "2147645572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Elvdeng"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 00 64 74 72 52 89 50 08 a3 ?? ?? ?? ?? 8d 88 e0 ff 00 00 be fd 07 00 00 eb 03}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\Progra~1\\lvegned\\config.ini" ascii //weight: 1
        $x_1_3 = {63 6f 6e 66 69 67 00 [0-3] 6e 61 76 69 67 61 74 65 75 72 6c 00 [0-3] 73 69 7a 65 00 [0-3] 48 4f 4f 4b 42 57}  //weight: 1, accuracy: Low
        $x_1_4 = {3a 5c 70 6c 75 67 69 6e 01 00 2e 02 00 5c 6c 69 62 5c 72 65 6c 65 61 73 65 5c 64 6c 6c 6f 6e 65 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

