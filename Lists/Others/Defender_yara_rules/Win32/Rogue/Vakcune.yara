rule Rogue_Win32_Vakcune_165170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Vakcune"
        threat_id = "165170"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Vakcune"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 50 6f 77 65 72 53 63 61 6e}  //weight: 1, accuracy: High
        $x_1_2 = {00 51 75 61 72 61 6e 74 69 6e 65 50 6f 77}  //weight: 1, accuracy: High
        $x_1_3 = "\\DelUS.bat" ascii //weight: 1
        $x_2_4 = {00 41 64 46 61 69 6c 65 64 52 65 70 61 69 72}  //weight: 2, accuracy: High
        $x_2_5 = {00 64 62 5c 70 77 64 62 2e 64 61 74 00}  //weight: 2, accuracy: High
        $x_2_6 = {00 41 64 77 61 72 65 2e 25 73 00 00 00 5b 73 79 73}  //weight: 2, accuracy: High
        $x_2_7 = "Ebiz Network" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

