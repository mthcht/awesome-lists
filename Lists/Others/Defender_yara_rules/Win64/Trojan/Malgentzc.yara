rule Trojan_Win64_Malgentzc_A_2147920877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Malgentzc.A!MTB"
        threat_id = "2147920877"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Malgentzc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 41 b9 00 30 00 00 41 b8 04 01 00 00 48 8b c8 ff 15 ?? ?? ?? ?? 48 8b e8 4c 8b 4b 10 49 ff c1 4c 8b c3 48 83 7b 18 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 4c 24 20 45 8b ce 41 b8 08 00 00 00 49 8b d4 48 8b 08 ff 15 ?? ?? ?? ?? 41 ff c7 48 83 c7 08 49 63 c7 48 3b c3 41 bc 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

