rule TrojanDownloader_Win32_Nurech_R_2147594783_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nurech.R"
        threat_id = "2147594783"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nurech"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "/get_exe.php?l=" wide //weight: 10
        $x_10_2 = {2e 00 65 00 78 00 65 00 0a 00 5c 00 ?? ?? (61|2d|7a|00) (61|2d|7a|00) ?? ?? (30|2d|39|00) (30|2d|39|00) 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_5_3 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 00 00 5c 64 65 6c 73 65 6c 66 2e 62 61 74 00 00 00 00 40 65 63 68 6f 20 6f 66 66 0a 3a 74 72 79 0a 64 65 6c 20 22 00 00 00 00 22 0a 69 66 20 65 78 69 73 74 20 22 00 00 00 00 22 20 67 6f 74 6f 20 74 72 79 0a 00 64 65 6c}  //weight: 5, accuracy: High
        $x_5_4 = {c6 85 d0 fb ff ff 5c c6 85 d1 fb ff ff 64 c6 85 d2 fb ff ff 65 c6 85 d3 fb ff ff 6c c6 85 d4 fb ff ff 73 c6 85 d5 fb ff ff 65 c6 85 d6 fb ff ff 6c c6 85 d7 fb ff ff 66 c6 85 d8 fb ff ff 2e c6 85 d9 fb ff ff 62 c6 85 da fb ff ff 61 c6 85 db fb ff ff 74}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Nurech_S_2147610520_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nurech.S"
        threat_id = "2147610520"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nurech"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 8b f0 c6 45 fc 7e e8 ?? ?? ff ff 50 8d 45 ec ff 36 68 ?? ?? 40 00 50}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 fc 57 50 e8 ?? ?? ff ff 83 c4 0c ff 30 8d 85 ?? ff ff ff c6 45 fc 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

