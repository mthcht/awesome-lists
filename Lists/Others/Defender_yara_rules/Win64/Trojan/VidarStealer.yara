rule Trojan_Win64_VidarStealer_ABA_2147955945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VidarStealer.ABA!MTB"
        threat_id = "2147955945"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff c2 0f b6 d2 44 0f b6 84 14 ?? ?? ?? ?? 44 00 c1 44 0f b6 c9 46 0f b6 94 0c ?? ?? ?? ?? 44 88 94 14 ?? ?? ?? ?? 46 88 84 0c ?? ?? ?? ?? 44 02 84 14 ?? ?? ?? ?? 45 0f b6 c0 46 0f b6 84 04 ?? ?? ?? ?? 45 30 04 04 48 ff c0 49 39 c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

