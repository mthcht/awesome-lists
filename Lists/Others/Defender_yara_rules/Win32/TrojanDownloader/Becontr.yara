rule TrojanDownloader_Win32_Becontr_A_2147687142_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Becontr.A"
        threat_id = "2147687142"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Becontr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "bts/e/g.php" ascii //weight: 1
        $x_1_2 = "/bts/23.php?" ascii //weight: 1
        $x_1_3 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\ERAWTFOS" ascii //weight: 1
        $x_1_4 = {41 50 50 44 41 54 41 [0-32] 4a 61 76 61 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = {6e 76 69 64 69 61 [0-32] 72 61 64 65 6f 6e}  //weight: 1, accuracy: Low
        $x_1_6 = {2f 62 74 73 2f 32 33 2e 70 68 70 3f 69 64 3d [0-32] 26 76 69 64 3d [0-32] 26 76 3d [0-32] 26 74 79 70 65 3d [0-32] 26 64 77 6e 6c 64 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

