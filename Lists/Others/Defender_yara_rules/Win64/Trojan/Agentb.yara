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

