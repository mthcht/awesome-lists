rule Trojan_Win64_Gobin_GVA_2147971867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Gobin.GVA!MTB"
        threat_id = "2147971867"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Gobin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 c0 0f 1f 84 00 00 00 00 00 85 c0 0f 84 15 04 00 00 69 d0 62 6c 00 00 c1 e8 10 31 d0 a9 0f 00 00 00 74 dc 89 c2 c1 e8 12 90 83 f8 20 77 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

