rule Trojan_Win32_Amatera_AMT_2147960835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amatera.AMT!MTB"
        threat_id = "2147960835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amatera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {50 8d 4d db e8 ?? ?? ?? ?? 89 45 d4 83 7d d4 00 75 16 68 d0 07 00 00 ff 15 ?? ?? ?? ?? 8b 4d fc 83 c1 01 89 4d fc}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amatera_MKS_2147962629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amatera.MKS!MTB"
        threat_id = "2147962629"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amatera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 08 89 4d f0 8b 55 f8 33 55 f0 81 e2 ff 00 00 00 89 55 ec 8b 45 f8 c1 e8 08 89 45 e4 c7 45 e8 ?? ?? ?? ?? 8b 4d ec 8b 55 e8 8b 04 8a 89 45 e0 8b 4d e4 33 4d e0 89 4d f8 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amatera_AME_2147963874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amatera.AME!MTB"
        threat_id = "2147963874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amatera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {89 1c 24 89 c6 8d 44 24 1c c7 44 24 08 40 00 00 00 89 74 24 04 89 44 24 0c ff d7 83 ec 10 89 74 24 08 89 6c 24 04 89 1c 24 e8 ?? ?? ?? ?? 8d 44 24 18 89 74 24 04 89 44 24 0c 8b 44 24 1c 89 1c 24 89 44 24 08 ff d7}  //weight: 3, accuracy: Low
        $x_2_2 = "iorlzupoahui" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amatera_LM_2147964015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amatera.LM!MTB"
        threat_id = "2147964015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amatera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {c7 45 b4 18 00 00 00 c7 45 b8 00 00 00 00 8d 55 cc 89 55 bc c7 45 c0 40 00 00 00 c7 45 e4 00 00 00 00 c6 45 f8 4e c6 45 f9 74 c6 45 fa 00 c6 45 d4 4f c6 45 d5 70 c6 45 d6 65 c6 45 d7 6e c6 45 d8 00 c6 45 f4 4b c6 45 f5 65 c6 45 f6 79 c6 45 f7 00 8d 45 d4}  //weight: 20, accuracy: High
        $x_10_2 = {83 c4 0c c6 45 fc 4e c6 45 fd 74 c6 45 fe 00 c6 45 d0 44 c6 45 d1 65 c6 45 d2 76 c6 45 d3 69 c6 45 d4 63 c6 45 d5 65 c6 45 d6 00 c6 45 f8 49 c6 45 f9 6f c6 45 fa 00 c6 45 c8 43 c6 45 c9 6f c6 45 ca 6e c6 45 cb 74 c6 45 cc 72 c6 45 cd 6f c6 45 ce 6c c6 45 cf 00 c6 45 d8 46 c6 45 d9 69 c6 45 da 6c c6 45 db 65 c6 45 dc 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

