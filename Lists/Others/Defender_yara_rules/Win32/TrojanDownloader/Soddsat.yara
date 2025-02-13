rule TrojanDownloader_Win32_Soddsat_A_2147654603_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Soddsat.A"
        threat_id = "2147654603"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Soddsat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 85 c0 75 05 b8 ?? ?? ?? ?? 50 68 04 00 00 80 6a 00 68 ?? ?? ?? ?? 68 02 00 00 00 bb 6c 02 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {44 3a 5c 77 69 6e 64 6f 73 2e 64 61 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

