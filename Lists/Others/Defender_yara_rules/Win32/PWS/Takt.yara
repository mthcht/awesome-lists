rule PWS_Win32_Takt_A_2147629319_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Takt.A"
        threat_id = "2147629319"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Takt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 76 6b 6f 6e 74 61 6b 74 65 2e 72 75 2f 67 69 66 74 73 2e 70 68 70 3f 61 63 74 3d 66 72 69 65 6e 64 73 00 00 00 4f 70 65 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 74 74 70 3a 2f 2f 76 6b 6f 6e 74 61 6b 74 65 2e 72 75 2f 67 69 66 74 73 2e 70 68 70 00 00 00 4f 70 65 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {1c 00 00 00 c2 e2 e5 e4 e8 f2 e5 20 e2 e0 f8 20 45 2d 6d 61 69 6c 20 e8 eb e8 20 cb ee e3 e8 ed 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 74 74 70 3a 2f 2f 68 61 6f 6d 61 2e 61 73 74 72 65 6e 64 2e 72 75 2f 73 6e 69 66 2e 70 68 70 3f 6c 6f 67 69 6e 3d 00 ff ff ff ff 06 00 00 00 26 70 61 73 73 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

