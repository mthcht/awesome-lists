rule Trojan_Win64_Dcrat_AMB_2147954337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dcrat.AMB!MTB"
        threat_id = "2147954337"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dcrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 83 78 18 0f 4e 8d 14 0a 49 8b c8 76 ?? 49 8b 08 33 d2 49 8b c1 49 f7 70 ?? 49 ff c1 0f b6 04 0a 41 30 02 49 8b 13 49 8b 43 08 48 2b c2 4c 3b c8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

