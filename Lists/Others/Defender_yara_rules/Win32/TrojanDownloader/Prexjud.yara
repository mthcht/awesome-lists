rule TrojanDownloader_Win32_Prexjud_A_2147629988_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Prexjud.A"
        threat_id = "2147629988"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Prexjud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 45 78 65 63 50 72 69 2e 64 6c 6c 00 68 69 67 68 00 45 78 65 63 57 61 69 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 72 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 4a 44 73 74 61 72 74 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

