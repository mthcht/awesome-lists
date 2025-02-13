rule Ransom_Win64_Donut_HUT_2147910216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Donut.HUT!MTB"
        threat_id = "2147910216"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 c9 45 29 c9 89 c8 31 d2 66 41 f7 f6 49 81 f9 4b 02 00 00 74 1a 6b c0 33 44 89 c2 28 c2 42 30 94 0c ?? ?? ?? ?? 49 ff c1 41 fe c0 ff c1 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

