rule TrojanDownloader_Win32_Safwin_A_2147652021_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Safwin.A"
        threat_id = "2147652021"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Safwin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 5c 57 69 6e 53 61 66 65 5c 4b 75 61 69 5a 69 70 5f 53 65 74 75 70 5f [0-10] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = ":\\Program Files\\360\\360Safe" ascii //weight: 1
        $x_1_3 = {68 74 74 70 3a 2f 2f 76 69 70 2e [0-10] 2e 63 6f 6d 3a 39 39 39 39 2f 53 75 62 6d 69 74 2e 70 68 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

