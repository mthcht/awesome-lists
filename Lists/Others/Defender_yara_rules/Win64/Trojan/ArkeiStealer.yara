rule Trojan_Win64_ArkeiStealer_ARS_2147961332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ArkeiStealer.ARS!MTB"
        threat_id = "2147961332"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 31 c0 47 8b 4c 3e ?? 45 31 e9 43 8b 04 3e 44 31 e0 41 0f b7 c9 41 c1 e9 ?? 89 c2 c1 ea}  //weight: 5, accuracy: Low
        $x_5_2 = {8d 48 ff 83 e1 1e 0f b6 8c 0d 40 03 00 00 30 4c 06 ff 89 c1 83 e1 1f 0f b6 8c 0d 40 03 00 00 30 0c 06 48 83 c0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

