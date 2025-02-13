rule Trojan_Win32_Hioles_A_2147646322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hioles.A"
        threat_id = "2147646322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hioles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c2 61 8b 45 08 03 45 fc 88 10 eb ?? 8b 4d 08 c6 41 09 2e 8b 55 08 c6 42 0a 64 8b 45 08 c6 40 0b 6c 8b 4d 08 c6 41 0c 6c 8b 55 08 c6 42 0d 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 6a 00 6a 01 8d 4d f4 51 6a 00 6a 00 6a 00 8d 55 ec 52 8b 45 f8 50 8b 4d e8 51 ff 55 f0 85 c0 7c ?? 6a 00 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hioles_B_2147648225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hioles.B"
        threat_id = "2147648225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hioles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b f9 c7 00 15 fb a4 68 c7 40 04 a0 65 b5 55}  //weight: 1, accuracy: High
        $x_1_2 = {8b 14 11 03 d1 03 d0 c1 ca 03 41 8b c2 3b 4c 24 08 72 e9 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hioles_D_2147648779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hioles.D"
        threat_id = "2147648779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hioles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 51 40 30 11 66 0f be 88 ?? ?? ?? ?? ba ?? ?? 00 00 66 0f af ca}  //weight: 1, accuracy: Low
        $x_1_2 = {66 8b c8 c1 e0 08 66 c1 e9 08 66 33 c8 8b 45 08 89 45 f4}  //weight: 1, accuracy: High
        $x_1_3 = {8b 0b 81 f9 47 45 54 20 74 ?? 81 f9 50 4f 53 54 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Hioles_C_2147652997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hioles.C"
        threat_id = "2147652997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hioles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 8b 11 ff d2 89 45 e8 8b 45 08 83 c0 14 50 8b 4d 08 8b 11 ff d2}  //weight: 1, accuracy: High
        $x_1_2 = {6a 40 6a 00 6a 01 8d 55 f8 52 6a 00 6a 00 6a 00 8d 45 ec 50 8b 4d fc 51 8b 55 08 52 ff 55 f0}  //weight: 1, accuracy: High
        $x_1_3 = {6a 40 56 6a 01 8d 45 f0 50 56 56 56 8d 45 f8 50 57 ff 75 08 ff 55 fc 85 c0}  //weight: 1, accuracy: High
        $x_1_4 = {8d 4e 08 89 4c 24 10 8b 4c 24 10 0f b7 09 66 8b d9 66 c1 eb 0c 66 85 db 74 ?? 66 83 fb 03 75 0b 23 cf 03 0e 03 4d 08 01 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Hioles_GMX_2147900773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hioles.GMX!MTB"
        threat_id = "2147900773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hioles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 c2 80 e2 ?? 20 de 88 cc 80 e4 ?? 20 dd 08 f2 08 ec 30 e2 88 95 ?? ?? ?? ?? 08 c8 34 ff 88 85 ?? ?? ?? ?? 8a 85 ?? ?? ?? ?? 8a 8d ?? ?? ?? ?? 8a 95 ?? ?? ?? ?? 80 ca 00 20 d1 08 c8 a8 01 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

