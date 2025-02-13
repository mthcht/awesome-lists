rule TrojanDownloader_Win32_Kucf_A_2147679526_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kucf.A"
        threat_id = "2147679526"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kucf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 75 63 6b 79 6f 75 61 6e 74 69 76 69 72 75 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {6c 6f 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = "cmd /c copy " ascii //weight: 1
        $x_1_4 = {6c 6f 67 2e 68 74 6d 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

