rule TrojanDownloader_Win32_Brcixdlr_A_2147628411_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Brcixdlr.A"
        threat_id = "2147628411"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Brcixdlr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 66 20 65 78 69 73 74 20 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 83 fb 03 74 2b 6a 00 6a 00 8b 45 f8 e8 ?? ?? ?? ?? 50 8b 45 fc e8 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 85 c0 75 d9 b2 01}  //weight: 1, accuracy: Low
        $x_1_3 = {68 c4 09 00 00 e8 ?? ?? ?? ?? 8d 55 ?? b8 24 00 00 00 e8 ?? ?? ?? ?? 8d 45 ?? 50 8d 4d ?? ba ?? ?? ?? ?? b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

