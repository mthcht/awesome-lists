rule TrojanDownloader_Win32_Npbro_A_2147657021_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Npbro.A"
        threat_id = "2147657021"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Npbro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 61 79 48 65 6c 6c 6f 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 11 52 a1 ?? ?? ?? ?? 8b 48 70 ff d1 83 c4 08}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 6a 00 8d 8d ?? ?? ?? ?? 51 8b 55 ?? 52 6a 00}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c2 01 52 a1 ?? ?? ?? ?? 8b 48 24 ff d1 83 c4 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

