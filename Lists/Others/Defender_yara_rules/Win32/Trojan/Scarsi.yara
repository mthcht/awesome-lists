rule Trojan_Win32_Scarsi_G_2147757119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scarsi.G!MTB"
        threat_id = "2147757119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 02 ff 45 ?? 81 7d [0-48] [0-48] 83 7d [0-48] 8b 45 [0-64] 8b 45 ?? 8a 80 [0-16] 34 0d 8b 55 ?? 03 55 ?? 88 02 [0-32] 8b 45 ?? 8a 80 ?? ?? ?? ?? 8b 55 ?? 03 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Scarsi_AXGR_2147794630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scarsi.AXGR!MTB"
        threat_id = "2147794630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xrkxjpwnv" wide //weight: 1
        $x_1_2 = "AdditiveSi34852262019" wide //weight: 1
        $x_1_3 = "prjAdditiveSinthesis.vbp" wide //weight: 1
        $x_1_4 = "ShoparaGrizli01" wide //weight: 1
        $x_1_5 = "Additive Sinthesis by Jorge flores.P." ascii //weight: 1
        $x_1_6 = "Make Wave---Hacer Wave" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Scarsi_ARA_2147835013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scarsi.ARA!MTB"
        threat_id = "2147835013"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 f9 ff 74 29 8b 35 40 90 40 00 b8 67 66 66 66 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 8d 14 80 03 d2 8b c1 2b c2 8a 90 c4 73 40 00 30 14 0e 41 3b 0d 4c 90 40 00 72 c9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Scarsi_ARA_2147835013_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scarsi.ARA!MTB"
        threat_id = "2147835013"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4d f0 83 c1 01 89 4d f0 8b 55 f0 3b 15 84 50 40 00 73 33 83 7d f0 00 7c 2b 8b 45 f0 99 b9 0a 00 00 00 f7 f9 8b 45 fc 0f be 0c 10 8b 15 6c 50 40 00 03 55 f0 0f be 02 33 c1 8b 0d 6c 50 40 00 03 4d f0 88 01 eb b9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Scarsi_GTB_2147949091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scarsi.GTB!MTB"
        threat_id = "2147949091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6b c8 00 c6 81 ?? ?? ?? ?? 6b ba 01 00 00 00 c1 e2 00 c6 82 ?? ?? ?? ?? 65 b8 01 00 00 00 d1 e0 c6 80 ?? ?? ?? ?? 72 b9 01 00 00 00 6b d1 03 c6 82 ?? ?? ?? ?? 6e b8 01 00 00 00 c1 e0 02 c6 80 ?? ?? ?? ?? 65 b9 01 00 00 00 6b d1 05 c6 82 ?? ?? ?? ?? 6c b8 01 00 00 00 6b c8 06 c6 81 ?? ?? ?? ?? 33 ba 01 00 00 00 6b c2 07 c6 80}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Scarsi_BAA_2147954673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scarsi.BAA!MTB"
        threat_id = "2147954673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 55 08 03 55 fc 0f be 1a e8 ?? ?? ?? ?? 33 d8 8b 45 08 03 45 fc 88 18 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

