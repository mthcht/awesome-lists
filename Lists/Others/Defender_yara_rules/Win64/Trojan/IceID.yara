rule Trojan_Win64_Iceid_PD_2147838898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Iceid.PD!MTB"
        threat_id = "2147838898"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Iceid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 f7 f1 48 8b c2 48 8b 4c 24 ?? 66 3b f6 74 45}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 48 8b c1 b9 08 00 00 00 3a db 74 ?? 8b c1 48 63 4c 24 ?? 48 8b 54 24}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 44 01 ?? 8b 4c 24 ?? 33 c8 66 3b ff 74 ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Iceid_PBF_2147849552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Iceid.PBF!MTB"
        threat_id = "2147849552"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Iceid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 48 8b c1 3a db b9 ?? ?? ?? ?? 48 f7 f1 3a c9 48 8b c2 48 8b 4c 24 ?? 3a c0 0f b6 44 01 ?? 8b 8c 24 ?? ?? ?? ?? 3a db 33 c8 8b c1 66 3b f6 48 63 4c 24 ?? 48 8b 94 24 ?? ?? ?? ?? 88 04 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Iceid_PBG_2147850677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Iceid.PBG!MTB"
        threat_id = "2147850677"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Iceid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8d 49 01 83 e0 03 ff c2 0f b6 44 38 2c 30 41 ff 3b d6 8b c2 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

