rule Worm_Win32_Playnro_A_2147695483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Playnro.A"
        threat_id = "2147695483"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Playnro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {63 6d 64 00 [0-16] 6f 70 65 6e 00 [0-32] 77 69 6e 6c 67 6e [0-5] 65 78 65}  //weight: 5, accuracy: Low
        $x_1_2 = {63 6f 70 79 [0-32] 2f 63 20 61 74 74 72 69 62 20 2d 68 20 2d 73}  //weight: 1, accuracy: Low
        $x_1_3 = "start new game" ascii //weight: 1
        $x_1_4 = {00 5c 4d 79 52 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

