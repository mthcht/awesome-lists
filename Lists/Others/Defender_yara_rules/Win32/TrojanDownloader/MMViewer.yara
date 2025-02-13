rule TrojanDownloader_Win32_MMViewer_2147804047_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/MMViewer"
        threat_id = "2147804047"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "MMViewer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 6d 76 69 65 77 65 72 2e 63 6f 6d 00 2f 70 6f 73 74 2f [0-48] 25 25 25 78 00 [0-16] 6c 6f 63 61 6c 68 6f 73 74 3a 38 30 38 30 00 00 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63}  //weight: 4, accuracy: Low
        $x_2_2 = "httppost_dll.DLL" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

