rule Trojan_Win64_XenoRAT_A_2147919785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XenoRAT.A!MTB"
        threat_id = "2147919785"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XenoRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 04 24 ff c0 89 04 24 8b 44 24 28 39 04 24 7d ?? 48 63 04 24 48 8b 4c 24 20 0f b6 04 01 0f b6 4c 24 30 33 c1 48 63 0c 24 48 8b 54 24 20 88 04 0a}  //weight: 2, accuracy: Low
        $x_4_2 = "aHR0cD" ascii //weight: 4
        $x_2_3 = "C:\\Users\\Public\\Downloads\\" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

