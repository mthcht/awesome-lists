rule TrojanDownloader_Win32_Ligzoc_B_2147697078_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ligzoc.B"
        threat_id = "2147697078"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ligzoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 32 36 74 79 70 65 25 33 44 30 25 32 36 6f 6e 65 25 33 44 31 25 32 36 74 77 6f 25 33 44 31 25 32 36 77 62 25 33 44 00}  //weight: 1, accuracy: High
        $x_1_2 = {26 74 79 70 65 3d 30 26 6f 6e 65 3d 31 26 74 77 6f 3d 31 26 77 62 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 32 36 70 63 6e 61 6d 65 25 33 44 00}  //weight: 1, accuracy: High
        $x_1_4 = {26 70 63 6e 61 6d 65 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {54 6f 6e 67 6a 69 00}  //weight: 1, accuracy: High
        $x_1_6 = {4f 72 61 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_7 = {43 3a 5c 54 45 4d 50 5c 5c 7a 2e 69 63 6f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

