rule TrojanDownloader_Win32_Ansis_F_2147648882_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ansis.F"
        threat_id = "2147648882"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ansis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {22 fd 9a 80 5c 73 69 2e 65 78 65 22 20 fd a1 80 20 2f 70 69 64 3d 36 36 00 6f 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

