rule TrojanDownloader_Win32_Xtrat_A_2147681485_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Xtrat.A"
        threat_id = "2147681485"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Xtrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 00 e8 ?? ?? ?? ?? 85 c0 0f 94 05 ?? ?? ?? ?? 6a 01 6a 00 6a 00 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 8b c3 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 80 3d ?? ?? ?? ?? 00 74 12 6a 02 a1 b8 a3 52 00 e8 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "TopModel-x-" wide //weight: 1
        $x_1_3 = "Password.exe" wide //weight: 1
        $x_1_4 = "CORE.ccc?attredirects=0&d=1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

