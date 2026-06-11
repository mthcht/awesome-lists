rule TrojanSpy_Win64_QuokkaShade_A_2147971378_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/QuokkaShade.A!dha"
        threat_id = "2147971378"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "QuokkaShade"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[LftMs]" wide //weight: 1
        $x_1_2 = "[RitMs]" wide //weight: 1
        $x_1_3 = {5c 00 45 00 6e 00 76 00 69 00 72 00 6f 00 6e 00 6d 00 65 00 6e 00 74 00 00 00 00 00 00 00 00 00 5c 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 55 00 73 00 65 00 72 00 5c 00 00 00 5d 00}  //weight: 1, accuracy: High
        $x_3_4 = {32 11 4c 8b c3 48 83 7b 18 0f 76 ?? 4c 8b 03 42 88 14 00 48 ff c0 48 ff c9 48 83 ef 01}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

