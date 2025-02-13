rule TrojanDropper_Win32_Lucuis_A_2147652820_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Lucuis.A"
        threat_id = "2147652820"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Lucuis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "789eric012" ascii //weight: 1
        $x_1_2 = {8b 44 24 0c 56 8d 70 3f 8b 44 24 08 83 e6 c0 85 c0 0f 84 ?? ?? 00 00 8b 44 24 0c 85 c0 0f 84 ?? ?? 00 00 8b 44 24 14 85 c0 (0f 84 ?? ??|74 ??) 85 f6 74 ?? 8b 4c 24 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

