rule TrojanDownloader_Win32_Gabeerf_A_2147644489_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gabeerf.A"
        threat_id = "2147644489"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gabeerf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 65 74 52 61 6e 64 6f 6d 00 2e [0-3] 00 56 42 53 46 69 6c 65 00 2e 74 62 69 63 6f 00}  //weight: 1, accuracy: Low
        $x_1_2 = ":777/loading/avbs.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

