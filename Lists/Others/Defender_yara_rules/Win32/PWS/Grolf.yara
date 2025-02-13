rule PWS_Win32_Grolf_A_2147624838_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Grolf.A"
        threat_id = "2147624838"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Grolf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ac 84 c0 74 09 2c 59 34 03 04 12 aa}  //weight: 2, accuracy: High
        $x_1_2 = {68 04 00 01 40 51 6a 00 ff d0 5f b0 01}  //weight: 1, accuracy: High
        $x_2_3 = {50 75 15 80 7c 34 ?? 41 75 0e 80 7c 34 ?? 53 75 07 80 7c 34 ?? 53}  //weight: 2, accuracy: Low
        $x_1_4 = {74 2f b2 0a 80 f9 0d 75 1c 38 94 04}  //weight: 1, accuracy: High
        $x_1_5 = "MSHELPDLL" wide //weight: 1
        $x_1_6 = "MSSECDRV" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

