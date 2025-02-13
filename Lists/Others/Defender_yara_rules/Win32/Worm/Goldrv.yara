rule Worm_Win32_Goldrv_A_2147690375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Goldrv.A"
        threat_id = "2147690375"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Goldrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_2_2 = "\\new folder" wide //weight: 2
        $x_1_3 = "Temp update file:" ascii //weight: 1
        $x_3_4 = "\\vertigodl" ascii //weight: 3
        $x_2_5 = {2e 76 76 73 2e 69 72 2f 00}  //weight: 2, accuracy: High
        $x_2_6 = {64 6c 76 65 72 73 69 6f 6e 2e 70 68 70 3f 69 64 3d [0-32] 64 6c 75 70 64 61 74 65 2e 64 61 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

