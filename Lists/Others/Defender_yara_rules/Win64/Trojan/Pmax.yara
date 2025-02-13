rule Trojan_Win64_Pmax_AP_2147891849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Pmax.AP!MTB"
        threat_id = "2147891849"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Pmax"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 05 68 53 01 00 48 89 15 79 53 01 00 48 8d 15 71 cb 00 00 48 89 0d 53 55 01 00 48 83 c1 30 48 89 15 90 53 01 00 48 8d 15 61 cb 00 00 48 89 0d 42 55 01 00 48 83 c1 30 48 89 05 1f 55 01 00 48 8b 05 08 eb 00 00 48 89 15 99 53 01 00 48 8d 15 43 cb 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

