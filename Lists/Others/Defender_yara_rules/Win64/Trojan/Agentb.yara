rule Trojan_Win64_Agentb_GDI_2147943974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Agentb.GDI!MTB"
        threat_id = "2147943974"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Agentb"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe 63 c8 62 49 8b c8 49 8b c1 49 f7 e0 49 ff c0 48 c1 ea 03 48 8d 04 d2 48 2b c8 8a 44 0c 50 42 30 44 04 77 49 83 f8 10}  //weight: 5, accuracy: High
        $x_5_2 = {33 c9 89 5c 24 ?? 83 64 24 ?? 00 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 48 8b 4c 24 ?? 4c 8d 4d ?? 48 8d 95 ?? ?? ?? ?? 45 33 c0 89 5c 24 ?? c7 44 24 ?? 00 30 00 00 ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Agentb_GXY_2147952149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Agentb.GXY!MTB"
        threat_id = "2147952149"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Agentb"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {46 32 14 1b 41 f7 f9 41 d2 ca 41 31 f2 83 c6 07 46 88 14 1b}  //weight: 5, accuracy: High
        $x_5_2 = {89 c8 99 41 f7 f9 48 63 d2 41 0f b6 04 10 41 30 04 0a 48 83 c1 01 49 39 cb 75 e5 c3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

