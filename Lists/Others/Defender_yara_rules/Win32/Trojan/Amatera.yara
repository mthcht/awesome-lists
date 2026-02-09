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

