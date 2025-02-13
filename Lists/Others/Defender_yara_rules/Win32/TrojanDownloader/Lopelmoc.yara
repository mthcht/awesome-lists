rule TrojanDownloader_Win32_Lopelmoc_A_2147640284_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lopelmoc.A"
        threat_id = "2147640284"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lopelmoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 7e 7d 25 0f be 55 cf 83 fa 4f 7d 0c 0f be 45 cf 83 c0 2f}  //weight: 1, accuracy: High
        $x_1_2 = {83 c1 01 89 8d ?? ?? ff ff 81 bd ?? ?? ff ff 80 96 98 00 7d 4e}  //weight: 1, accuracy: Low
        $x_1_3 = {6b c0 3c 69 c0 e8 03 00 00 50 ff 15 ?? ?? ?? ?? 8b 8d ?? ?? ff ff d1 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

