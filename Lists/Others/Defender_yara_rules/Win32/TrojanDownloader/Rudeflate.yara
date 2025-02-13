rule TrojanDownloader_Win32_Rudeflate_A_2147619221_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rudeflate.gen!A"
        threat_id = "2147619221"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rudeflate"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 01 00 00 00 8b 0d ?? ?? ?? ?? 80 74 01 ff ?? 40 4a 75 f1}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d8 c7 43 08 0f 00 00 00 83 ce ff 66 b9 50 00 8b 55 ?? 8b c3 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

