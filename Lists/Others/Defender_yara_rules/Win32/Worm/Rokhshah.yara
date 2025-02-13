rule Worm_Win32_Rokhshah_A_2147606770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rokhshah.A"
        threat_id = "2147606770"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rokhshah"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4e 65 74 77 6f 72 6b 20 53 65 72 76 69 63 65 73 00 00 00 00 53 6f 66 74 77 61 72 65 5c 53 65 72 76 69 63 65 00 00 00 00 56 65 72 73 69 6f 6e 00 5c 74 6d 70 2e 65 78 65 00 00 00 00 74 6d 70 2e 65 78 65 ?? ?? ?? ?? ?? 53 68 61 68 72 6f 6b 68 2e 65 78 65 00 00 00 00 61 75 74 6f 72 75 6e 2e 65 78 65}  //weight: 5, accuracy: Low
        $x_3_2 = "Administrator\\Desktop\\myPenDriveDetect\\release\\myPenDriveDetect.pdb" ascii //weight: 3
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL" ascii //weight: 1
        $x_1_4 = {66 3a 5c 2a 2e 65 78 65 00 00 00 00 25 63 3a 5c 61 75 74 6f 72 75 6e 2e 65 78 65 00 25 63 3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 00 25 63 3a 5c 2a 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_5 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 00 00 61 75 74 6f 72 75 6e 2e 69 6e 66 00 53 79 73 74 65 6d 52 6f 6f 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

