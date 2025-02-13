rule Trojan_Win64_LoaderCS_ZZ_2147778499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LoaderCS.ZZ"
        threat_id = "2147778499"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LoaderCS"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 53 48 83 ec 20 8b 1d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? ba 73 10 00 00 ff 15 ?? ?? ?? ?? 4c 8b d8 8b 05 ?? ?? ?? ?? 41 03 c3 8b c8 48 8b 05 ?? ?? ?? ?? 0f b6 0c 08 48 8b 05 ?? ?? ?? ?? 0f b6 14 18 03 d1 8b 0d ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 88 14 08 48 83 c4 20 5b c3}  //weight: 1, accuracy: Low
        $x_1_2 = {48 83 c4 40 ff e1}  //weight: 1, accuracy: High
        $x_1_3 = {2d 35 19 00 00 89 44 ?? ?? 41 b9 00 30 00 00 44 8b ?? ?? ?? 33 d2 48 8b ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

