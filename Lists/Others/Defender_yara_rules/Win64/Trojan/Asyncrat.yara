rule Trojan_Win64_Asyncrat_LM_2147948582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Asyncrat.LM!MTB"
        threat_id = "2147948582"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Asyncrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 83 ec 28 48 85 d2 74 2d 83 7a 08 06 75 ?? 48 b8 46 00 6f 00 72 00 6d 00 48 33 42 0c 44 8b 42 14 41 81 f0 61 00 74 00 49 0b c0 75 ?? 48 8b 81 88 00 00 00 eb}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

