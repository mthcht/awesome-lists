rule Worm_Win32_Ramnit_A_2147636562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ramnit.A"
        threat_id = "2147636562"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 8f 47 08 89 57 10 68 20 00 00 e0 8f 47 24}  //weight: 1, accuracy: High
        $x_1_2 = {76 67 2d 09 00 00 00 6a 00 6a 00 05 00 3d 09 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {b0 e2 88 06 46 ff 75 10 56 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

