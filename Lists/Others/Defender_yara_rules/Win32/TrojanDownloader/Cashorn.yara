rule TrojanDownloader_Win32_Cashorn_A_2147610969_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cashorn.A"
        threat_id = "2147610969"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cashorn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 be 90 01 00 00 06 75 43 0f b6 86 99 01 00 00 0f b6 8e 98 01 00 00 0f b6 96 97 01 00 00 50 0f b6 86 96 01 00 00 51 0f b6 8e 95 01 00 00 52 0f b6 96 94 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 40 9c 00 00 8d 8c 24 ?? 00 00 00 6a 00 51 e8 ?? ?? ?? ?? 83 c4 0c 68 3f 9c 00 00 8d 94 24 ?? 00 00 00 52 8d 4c 24 ?? e8 ?? ?? ?? ?? 85 c0 75 bd}  //weight: 1, accuracy: Low
        $x_2_3 = {3f 66 69 6c 65 3d 73 65 74 75 70 26 73 74 61 74 75 73 3d 64 69 66 66 64 61 74 65 00}  //weight: 2, accuracy: High
        $x_2_4 = {43 61 73 68 6f 6e 75 70 64 61 74 65 00}  //weight: 2, accuracy: High
        $x_2_5 = {2f 6c 6f 67 2f 75 70 64 61 74 65 2e 70 68 70 3f 00}  //weight: 2, accuracy: High
        $x_2_6 = {2f 64 6f 77 6e 6c 6f 61 64 2f 72 75 6e 5f 64 6c 69 73 74 2e 74 78 74 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

