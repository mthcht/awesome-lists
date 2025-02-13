rule TrojanDownloader_Win32_Hardy_A_2147626507_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hardy.A"
        threat_id = "2147626507"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hardy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {38 00 00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 39 00 38 00 2e 00 31 00 30 00 36 00 2e 00 32 00 32 00 37 00 2e 00 35 00 38 00 2f 00 75 00 6e 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {38 00 00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 39 00 38 00 2e 00 31 00 30 00 36 00 2e 00 32 00 32 00 37 00 2e 00 35 00 38 00 2f 00 54 00 6f 00 6f 00 6c 00 73 00 2e 00 7a 00 69 00 70 00}  //weight: 1, accuracy: High
        $x_5_3 = "\\temp2\\Hydra- NOVO\\fonte\\Drive Hydra\\Project" wide //weight: 5
        $x_5_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00 00 d0 2d 40 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

