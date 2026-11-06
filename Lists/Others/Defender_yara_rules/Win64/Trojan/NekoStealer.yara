rule Trojan_Win64_NekoStealer_DP_2147981683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NekoStealer.DP!MTB"
        threat_id = "2147981683"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NekoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 04 0b 31 d2 31 c8 30 e8 41 89 c1 89 c8 41 f7 f2 44 32 8c 14 a0 00 00 00 44 88 0c 0b 48 83 c1 01 49 39 c8 75}  //weight: 5, accuracy: High
        $x_1_2 = "ChainingModeCBC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

