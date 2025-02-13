rule TrojanDownloader_Win32_Potentialdownloader_A_2147641866_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Potentialdownloader.A"
        threat_id = "2147641866"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Potentialdownloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 e8 04 00 00 00 ?? ?? ?? ?? 58 2b 00 ff 10}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 75 fc e8 ?? 00 00 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_3 = {64 a1 30 00 00 00 8b 40 0c 8b 70 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

