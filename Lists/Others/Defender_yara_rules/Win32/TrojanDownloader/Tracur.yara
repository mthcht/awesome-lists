rule TrojanDownloader_Win32_Tracur_AH_2147651373_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tracur.AH"
        threat_id = "2147651373"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "srfivveuelub.dll" ascii //weight: 1
        $x_1_2 = "http://213.174.141.11/xml?a=" ascii //weight: 1
        $x_1_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e [0-32] 67 6f 6f 67 6c 65 20 66 61 63 65 62 6f 6f 6b 20 62 69 6e 67 20 79 61 68 6f 6f 20 61 6f 6c 20 79 6f 75 74 75 62 65 20 6d 73 6e 20 68 6f 74 6d 61 69 6c 20 67 6d 61 69 6c [0-32] 2e 63 6f 6d 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

