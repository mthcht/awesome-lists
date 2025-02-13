rule TrojanDownloader_Win32_Kepma_A_2147679080_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kepma.A"
        threat_id = "2147679080"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kepma"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "wemake.adntop.com/" ascii //weight: 1
        $x_1_2 = {70 61 72 74 ?? ?? 00 00 63 6f 64 65 00 00 00 00 44 45 46 41 55 4c 54 5f 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {77 65 6d 61 6b 65 70 70 6f 70 5c 63 6e 73 2e 64 61 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

