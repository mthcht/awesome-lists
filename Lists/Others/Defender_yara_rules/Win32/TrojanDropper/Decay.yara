rule TrojanDropper_Win32_Decay_A_2147630810_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Decay.A"
        threat_id = "2147630810"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Decay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 99 f7 fe 41 8a 82 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 83 f9 0a 7e e9 33 c9 8d a4 24 00 00 00 00}  //weight: 1, accuracy: Low
        $x_2_2 = {7e e9 bf 01 00 00 00 bb 02 00 00 00 bd 03 00 00 00 b8 04 00 00 00 33 c9}  //weight: 2, accuracy: High
        $x_1_3 = {8b 10 89 16 8a 48 04 88 4e 04 83 c6 05 c6 06 e9 46 2b c6 40 89 06 83 ee 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

