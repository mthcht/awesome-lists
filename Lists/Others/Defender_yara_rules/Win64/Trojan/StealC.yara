rule Trojan_Win64_Stealc_RPX_2147894330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealc.RPX!MTB"
        threat_id = "2147894330"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 10 00 00 77 47 00 00 f8 ?? 19 00 77 47 00 00 98 47 00 00 1c ?? 19 00 98 47 00 00 b9 47 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

