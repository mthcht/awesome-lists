rule TrojanDownloader_Win32_Argnot_A_2147656537_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Argnot.A"
        threat_id = "2147656537"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Argnot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {74 0b 8b 45 e4 83 e8 04 8b 00 89 45 e4 8b 45 e4 85 c0 7e 40 89 45 e8 c7 45 f0 01 00 00 00 8d 45 e0 ba ?? ?? ?? ?? 8b 4d f4 66 8b 54 4a fe 8b 4d fc 8b 5d f0 66 8b 4c 59 fe 66 33 d1 e8 ?? ?? ?? ?? 8b 55 e0 8d 45 ec}  //weight: 10, accuracy: Low
        $x_1_2 = "avsche.exe" wide //weight: 1
        $x_1_3 = "EASend.dll" wide //weight: 1
        $x_1_4 = "nota.rar" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

