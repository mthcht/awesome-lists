rule TrojanDownloader_Win32_Tufik_A_2147616984_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tufik.A"
        threat_id = "2147616984"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tufik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 49 47 52 45 53 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {64 6f 77 6e 6c 6f 61 64 00 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73}  //weight: 1, accuracy: High
        $x_1_3 = "MY_MAIN_JNJECT" ascii //weight: 1
        $x_1_4 = "IEHlprObj.IEHlprObj.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

