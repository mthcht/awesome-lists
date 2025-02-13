rule TrojanDownloader_Win32_Chaneeks_A_2147686625_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chaneeks.A"
        threat_id = "2147686625"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chaneeks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 86 57 0d 00 68 88 4e 0d 00 e8 1a 00 00 00 89 45 fc 68 fa 8b 34 00 68 88 4e 0d 00}  //weight: 1, accuracy: High
        $x_1_2 = {8d 44 24 04 8d 4c 24 00 50 51 e8 ?? ?? ff ff 83 c4 08 68 ?? ?? ?? ?? ff 54 24 04 68 ?? ?? ?? ?? 89 44 24 ?? ff 54 24 04 68 ?? ?? ?? ?? 50 89 44 24 ?? ff 54 24 0c 8b 54 24 ?? 68 ?? ?? ?? ?? 52 89 44 24 ?? ff 54 24 0c 89 44 24 ?? 8d 44 24 00 50 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

