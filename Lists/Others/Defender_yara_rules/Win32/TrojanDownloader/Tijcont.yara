rule TrojanDownloader_Win32_Tijcont_A_2147657657_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tijcont.A"
        threat_id = "2147657657"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tijcont"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 76 6f 68 63 73 74 2e 65 78 65 00 [0-64] 44 6f 77 6e 6c 6f 61 64 00}  //weight: 1, accuracy: Low
        $x_1_2 = "D:\\windows\\system32\\taskmgr.exe" ascii //weight: 1
        $x_1_3 = {3a 31 33 31 34 2f 74 6a [0-1] 2f 43 6f 75 6e 74 2e 61 73 70 3f 6d 61 63 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

