rule Trojan_Win32_SectopRAT_DA_2147916431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SectopRAT.DA!MTB"
        threat_id = "2147916431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SectopRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f9 d9 32 00 00 74 ?? 31 d2 89 c8 bb 17 00 00 00 f7 f3 0f b6 81 ?? ?? ?? ?? 0f b6 9a ?? ?? ?? ?? 31 d8 88 81 ?? ?? ?? ?? 41 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 c7 44 24 ?? ?? ?? ?? ?? 8b c6 8d 0c 1e f7 74 24 ?? 03 d7 8a 44 14 ?? 32 04 29 46 88 01 81 fe 00 36 0d 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

