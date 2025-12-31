rule Trojan_Win64_Bobik_CZP_2147840683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bobik.CZP!MTB"
        threat_id = "2147840683"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {44 8b d0 eb ?? ?? c1 e2 04 eb ?? ?? ?? 41 c1 ea 05 eb ?? ?? ?? 41 33 d2 71 ?? 69 07 ?? ?? ?? ?? 01 2c 45 8b d4 eb 02 03 70 41 8b cc eb ?? ?? ?? c1 e9 0b eb ?? ?? ?? ?? 83 e1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bobik_SX_2147958010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bobik.SX!MTB"
        threat_id = "2147958010"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {83 c0 1f 99 f7 f9 0f af c5 8d 1c ?? ?? ?? ?? ?? 44 8d 73 ?? 4c 89 f1}  //weight: 15, accuracy: Low
        $x_10_2 = {48 8d 44 24 60 48 89 c6 f3 a5 48 89 44 24 28 49 8d 45 36 4c 89 e1 89 54 24 30 4c 89 fa 4c 89 ee 48 89 44 24 20 ff 15}  //weight: 10, accuracy: High
        $x_1_3 = "/bot%s/sendPhoto" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bobik_AHB_2147960340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bobik.AHB!MTB"
        threat_id = "2147960340"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {c7 44 24 48 59 00 00 00 c7 44 24 48 5e 00 00 00 c7 44 24 48 63 00 00 00 c7 44 24 48 68 00 00 00}  //weight: 30, accuracy: High
        $x_20_2 = {89 f1 48 69 c9 ?? ?? ?? ?? 48 c1 e9 ?? 48 01 c1 48 39 c1 0f 93 c0 84 c0 74}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

