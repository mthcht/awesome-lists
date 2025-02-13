rule TrojanDownloader_Win32_Zloader_STA_2147771104_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zloader.STA"
        threat_id = "2147771104"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a 0c 68 ?? ?? 00 10 68 ?? ?? 00 10 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 0c 0f be 0c 10 33 d9 8b 55 f8 03 55 fc 88 1a}  //weight: 1, accuracy: High
        $x_1_3 = {6c 6f 61 64 65 72 5f 78 6c 73 2e 64 6c 6c 00 49 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

