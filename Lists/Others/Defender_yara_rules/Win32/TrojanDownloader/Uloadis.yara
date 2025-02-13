rule TrojanDownloader_Win32_Uloadis_A_2147610250_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Uloadis.A"
        threat_id = "2147610250"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Uloadis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_2 = "drivers\\etc\\hosts" ascii //weight: 1
        $x_1_3 = {53 65 74 45 6e 74 72 69 65 73 49 6e 41 63 6c 41 00}  //weight: 1, accuracy: High
        $x_2_4 = {5b c3 6e 74 6f 73 6b 72 6e 6c 2e 65 78 65 00 00 00 00 4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 00 00 00 00 55 8b ec 33}  //weight: 2, accuracy: High
        $x_3_5 = {be 00 40 00 00 6a 04 68 00 30 00 00 56 6a 00 e8 ?? ?? ff ff 8b d8 85 db 74 45 6a 00 56 53 55 e8 ?? ?? ff ff 8b f8 81 ff 04 00 00 c0 75 13 68 00 80 00 00}  //weight: 3, accuracy: Low
        $x_1_6 = {66 81 3b 4d 5a 75 ?? 03 43 3c 0f b7 48 14 81 f9 e0 00 00 00 75 ?? 8b d0 83 c2 18 8b ca 81 c1 e0 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

