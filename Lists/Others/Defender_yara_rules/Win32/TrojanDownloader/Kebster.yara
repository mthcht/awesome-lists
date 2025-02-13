rule TrojanDownloader_Win32_Kebster_A_2147689342_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kebster.A"
        threat_id = "2147689342"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kebster"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 64 71 6e 65 77 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {2f 62 6e 65 77 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 78 31 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 6e 67 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {2f 62 65 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {2f 7a 70 6d 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {2f 61 6e 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {2f 73 70 6d 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_9 = {f3 a5 8b ca 50 83 e1 03 f3 a4 8d 44 24 18 50 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 8d 4c 24 10 6a 00 51 ff d5 68 10 27 00 00 ff 15 ?? ?? ?? ?? 8d 54 24 10 68 80 00 00 00 52 ff 15 ?? ?? ?? ?? 8d 44 24 10 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

