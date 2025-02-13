rule TrojanDropper_Win32_Maener_A_2147688932_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Maener.A"
        threat_id = "2147688932"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Maener"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Mining_framework\\" ascii //weight: 2
        $x_2_2 = {00 52 61 75 6d 20 45 78 74 72 61 63 74}  //weight: 2, accuracy: High
        $x_1_3 = {00 5c 69 6e 74 65 6c 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = "original_exe_lol" ascii //weight: 1
        $x_5_5 = {8b c3 c1 e8 10 88 06 8b c3 c1 e8 08 88 46 01 88 5e 02 83 c6 03 bb 01 00 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

