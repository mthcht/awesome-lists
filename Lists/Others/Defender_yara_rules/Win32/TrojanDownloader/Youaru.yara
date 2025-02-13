rule TrojanDownloader_Win32_Youaru_A_2147611500_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Youaru.A"
        threat_id = "2147611500"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Youaru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 0a 80 f1 11 88 08 40 fe ca 75 f0}  //weight: 1, accuracy: High
        $x_1_2 = {6a ff 6a 14 e8 ?? ?? ff ff fe cb 75 bc 8b 0e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

