rule Worm_Win32_Rimcoss_A_2147610887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rimcoss.A"
        threat_id = "2147610887"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rimcoss"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 7c 24 04 00 00 80 3e 73 11 8b 44 24 00 85 c0 75 09 32 c0}  //weight: 1, accuracy: High
        $x_1_2 = {74 47 8d 4c 24 14 8d 54 24 38 51 52 ff d7 85 c0 74 09 66 81 7c 24 14 d0 07 72 2e}  //weight: 1, accuracy: High
        $x_1_3 = {8b 54 24 08 6a 00 6a 00 68 19 02 00 00 52 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {5b 41 75 74 6f 52 75 6e 5d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

