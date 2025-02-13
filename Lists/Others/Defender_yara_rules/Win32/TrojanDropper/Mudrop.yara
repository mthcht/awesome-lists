rule TrojanDropper_Win32_Mudrop_L_2147607331_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Mudrop.L"
        threat_id = "2147607331"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Mudrop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 38 2a 75 ?? a1 ?? ?? 40 00 03 05 ?? ?? 40 00 40 80 38 31 75 ?? a1 ?? ?? 40 00 03 05 ?? ?? 40 00 83 c0 02 80 38 2a 75}  //weight: 1, accuracy: Low
        $x_2_2 = {80 38 2a 75 ?? a1 ?? ?? 40 00 03 05 ?? ?? 40 00 40 80 38 36 75 ?? a1 ?? ?? 40 00 03 05 ?? ?? 40 00 83 c0 02 80 38 2a 75 51 a1 ?? ?? 40 00 03 05 ?? ?? 40 00 83 c0 03 80 38 2e 75 3e a1 ?? ?? 40 00 03 05 ?? ?? 40 00 83 c0 04 80 38 65 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

