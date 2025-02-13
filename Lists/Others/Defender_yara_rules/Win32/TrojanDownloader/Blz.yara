rule TrojanDownloader_Win32_Blz_A_2147626104_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Blz.A"
        threat_id = "2147626104"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Blz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 68 43 32 33 70 53 64 61 5a 4d 64 4d 76 46 48 31 66 65 33 35 7a 77 4f 43 75 77 00 6e 74 64 6c 6c 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_2 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 20 38 00 25 61 70 70 64 61 74 61 25}  //weight: 1, accuracy: High
        $x_1_3 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_4 = "InternetReadFile" ascii //weight: 1
        $x_1_5 = {68 d4 31 40 00 50 ff 15 18 20 40 00 56 56 56 6a 01 68 14 31 40 00 ff 15 20 32 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

