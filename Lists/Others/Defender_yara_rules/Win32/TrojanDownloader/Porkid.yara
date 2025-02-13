rule TrojanDownloader_Win32_Porkid_A_2147661386_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Porkid.A"
        threat_id = "2147661386"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Porkid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 50 68 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 52 ff 15 ?? ?? ?? ?? 89 45 ?? 83 7d ?? 00 74 ?? 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {65 63 68 6f 20 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 72 75 6e 20 22 [0-16] 2e 62 61 74 22 2c 30 2c 74 72 75 65 20 3e 3e}  //weight: 1, accuracy: Low
        $x_1_3 = "/wp/GEO/geo.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

