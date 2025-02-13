rule Worm_Win32_Wrasp_2147595860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Wrasp"
        threat_id = "2147595860"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Wrasp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/power.asp?" ascii //weight: 2
        $x_1_2 = {3a 5c 41 75 74 6f 72 75 6e 2e 69 6e 66 00}  //weight: 1, accuracy: High
        $x_1_3 = {5b 61 75 74 6f 72 75 6e 5d 0a 6f 70 65 6e 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {0a 73 68 65 6c 6c 65 78 65 63 75 74 65 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 74 61 72 74 20 50 61 67 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 75 73 65 72 69 6e 69 74 2e 65 78 65 2c 00}  //weight: 1, accuracy: High
        $x_1_7 = "Software\\Microsoft\\windows\\CurrentVersion\\explorer\\Advanced\\Folder\\Hidden\\SHOWALL" ascii //weight: 1
        $x_1_8 = {25 30 35 64 25 30 35 64 25 30 33 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

