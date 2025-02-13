rule TrojanDownloader_Win32_Neurevt_A_2147684718_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Neurevt.A"
        threat_id = "2147684718"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Neurevt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 6c 00 64 00 72 00 2d 00 25 00 30 00 38 00 58 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 c1 a0 00 00 00 89 4d ?? 8b 55 ?? 8b 45 0c 2b 42 34 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

