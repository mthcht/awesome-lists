rule Trojan_Win32_Jhee_A_2147597210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jhee.A"
        threat_id = "2147597210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jhee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 65 6e 64 6f 72 5f 53 68 61 72 65 4d 65 6d 6f 72 79 00 00 6d 69 63 72 6f 73 6f 66 74 5f 6c 6f 63 6b 00 00 25 75 00 00 43 3a 5c 00 75 3d 00 00 5b 6d 61 69 6e 5d 00 00 76 3d 00 00 25 73 00 00 22 2c 41 6c 77 61 79 73 00 00 00 00 72 75 6e 64 6c 6c 33 32 20 22 00 00 25 73 5c 44 6f 77 6e 6c 6f 7e 31 5c 25 73 2e 64 6c 6c 00 00 66 6b 77 00 50 4f 53 54 00 00 00 00 48 54 54 50 2f 31 2e 31 00 00 00 00 2a 2f 2a 00 54 4d 00 00 53 6f 66 74 77 61 72 65 5c 41 44 00}  //weight: 1, accuracy: High
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\po" ascii //weight: 1
        $x_1_3 = "licies\\Explorer\\Run" ascii //weight: 1
        $x_1_4 = "NefkheU<010<H>1$9?M:$=m1:$H<::$08>=0M0>:M01" ascii //weight: 1
        $x_1_5 = "WinSta0\\Default" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jhee_G_2147602140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jhee.G"
        threat_id = "2147602140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jhee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "NefkheU" ascii //weight: 1
        $x_1_2 = "WriteProcessMemory" ascii //weight: 1
        $x_1_3 = "CreateRemoteThread" ascii //weight: 1
        $x_1_4 = {74 5a 6a 00 57 8b 4d 0c 51 56 53 ff 15 ?? ?? ?? 10 85 c0 74 47 68 ?? ?? ?? 10 68 ?? ?? ?? 10 ff 15 ?? ?? ?? 10 50 ff 15 ?? ?? ?? 10 89 45 ?? 85 c0 74 29 6a 00 6a 00 56 50 6a 00 6a 00 53 ff 15 ?? ?? ?? 10 8b f8 89 7d ?? 85 ff 74 12 6a ff 57 ff 15 ?? ?? ?? 10 c6 45 ?? ?? eb 03}  //weight: 1, accuracy: Low
        $x_1_5 = {68 d0 07 00 00 ff d6 8d 54 24 08 52 57 e8 ?? ?? ?? ff 83 c4 08 85 c0 74 e7 5e}  //weight: 1, accuracy: Low
        $x_1_6 = {25 0f 00 00 80 79 05 48 83 c8 f0 40 83 c0 05 85 c0 7e 0c 8b f0 68 ?? ?? ?? ?? ff d7 4e 75 f6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Jhee_2147602359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jhee"
        threat_id = "2147602359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jhee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 a5 8b c8 33 c0 83 e1 03 8d ?? ?? ?? f3 a4 bf ?? ?? ?? ?? 83 c9 ff f2 ae f7 d1 2b f9 50 8b f7 8b fa 8b d1 83 c9 ff f2 ae 8b ca 4f c1 e9 02 f3 a5 68 80 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "up.dll.zgx" ascii //weight: 1
        $x_1_3 = "sysoption.ini" ascii //weight: 1
        $x_1_4 = "miniDll.dll.zgx" ascii //weight: 1
        $x_1_5 = "\\Explorer\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jhee_V_2147604770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jhee.V"
        threat_id = "2147604770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jhee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c9 ff 33 c0 f2 ae f7 d1 49 8b f9 85 ff 7e 26 8b 4c 24 10 8a 54 24 14 53 55 8b c1 2b f1 8b ef 8a 1c 06 32 da 88 18 40 4d 75 f5 5d c6 04 0f 00 5b 5f 5e c2 0c 00 8b 4c 24 10 5f 5e c6 04 08 00 c2 0c 00}  //weight: 2, accuracy: High
        $x_2_2 = {75 52 8b 8e 4c 01 00 00 8b 96 48 01 00 00 51 8d 46 04 52 50 68 ?? ?? 41 00 e8 ?? ?? 00 00 83 c4 10 8b ce e8 ?? ?? 00 00 85 c0 b8 ?? ?? 41 00 75 05}  //weight: 2, accuracy: Low
        $x_1_3 = "winio.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Jhee_H_2147616520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jhee.H"
        threat_id = "2147616520"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jhee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WriteProcessMemory" ascii //weight: 1
        $x_1_2 = "CreateRemoteThread" ascii //weight: 1
        $x_1_3 = {74 5a 6a 00 57 8b 4d 0c 51 56 53 ff 15 ?? ?? ?? 10 85 c0 74 47 68 ?? ?? ?? 10 68 ?? ?? ?? 10 ff 15 ?? ?? ?? 10 50 ff 15 ?? ?? ?? 10 89 45 ?? 85 c0 74 29 6a 00 6a 00 56 50 6a 00 6a 00 53 ff 15 ?? ?? ?? 10 8b f8 89 7d ?? 85 ff 74 12 6a ff 57 ff 15 ?? ?? ?? 10 c6 45 ?? ?? eb 03}  //weight: 1, accuracy: Low
        $x_1_4 = {68 d0 07 00 00 ff d6 8d 54 24 08 52 57 e8 ?? ?? ?? ff 83 c4 08 85 c0 74 e7 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

