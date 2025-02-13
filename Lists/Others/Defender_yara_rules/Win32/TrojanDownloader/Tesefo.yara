rule TrojanDownloader_Win32_Tesefo_A_2147606016_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tesefo.A"
        threat_id = "2147606016"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tesefo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 25 b8 01 00 00 00 83 f8 06 7f 1b 80 7c 03 ff 30 74 10 b9 06 00 00 00 2b c8 bf 01 00 00 00 d3 e7 09 3e 40 4a 75 e0}  //weight: 1, accuracy: High
        $x_1_2 = {ba 08 02 00 00 b8 12 00 00 00 e8 ?? ?? ?? ?? 50 8b 03 50 e8 ?? ?? ?? ?? 6a 00 8d 45 fc 50 6a 3e 8d 85 ca fa ff ff 50 8b 03 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

