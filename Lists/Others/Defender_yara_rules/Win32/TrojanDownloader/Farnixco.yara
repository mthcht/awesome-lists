rule TrojanDownloader_Win32_Farnixco_A_2147611248_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Farnixco.gen!A"
        threat_id = "2147611248"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Farnixco"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6f 00 77 00 73 00 5c 00 00 0b 76 00 61 00 6c 00 75 00 65 00 00 59 66 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 64 00 69 00 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 4a 00 75 00 6c 00 79 00 20 00 32 00 30 00 30 00 36 00 29 00 2f 00 68 00 6f 00 73 00 74 00 73 00 00 37 65 00 78 00 70 00 6c 00 6f 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = {6f 62 6a 5c 52 65 6c 65 61 73 65 5c 78 6f 63 6f 70 68 61 72 6f 6e 69 78 2e 70 64 62 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {78 6f 63 6f 70 68 61 72 6f 6e 69 78 00 78 6f 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

