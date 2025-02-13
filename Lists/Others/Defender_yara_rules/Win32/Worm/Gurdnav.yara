rule Worm_Win32_Gurdnav_A_2147651181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gurdnav.A"
        threat_id = "2147651181"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gurdnav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 e0 00 00 00 80 c7 45 e4 01 00 00 80 c7 45 e8 02 00 00 80 c7 45 ec 03 00 00 80}  //weight: 1, accuracy: High
        $x_1_2 = {64 6f 63 75 6d 65 6e 74 2e 6c 6f 63 61 74 69 6f 6e 2e 68 72 65 66 3d 27 68 74 74 70 3a 2f 2f [0-16] 3a 38 31 38 32 2f 33 2e 68 74 6d}  //weight: 1, accuracy: Low
        $x_1_3 = {61 75 74 6f 72 75 6e 2e 69 6e 66 [0-16] 5b 41 75 74 6f 52 75 6e 5d [0-16] 73 68 65 6c 6c 65 78 65 63 75 74 65 3d}  //weight: 1, accuracy: Low
        $x_1_4 = {73 68 75 74 64 6f 77 6e 2e 65 78 65 [0-16] 2d 72 20 2d 66 20 2d 74 20 30 31}  //weight: 1, accuracy: Low
        $x_1_5 = "Restart_%X Kill_%X=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

