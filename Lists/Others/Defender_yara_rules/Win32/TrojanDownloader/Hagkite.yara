rule TrojanDownloader_Win32_Hagkite_A_2147634499_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hagkite.A"
        threat_id = "2147634499"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hagkite"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 4c 04 50 40 83 f8 40 7c ed 68 ?? ?? ?? ?? e8 09 00 8a 88 ?? ?? ?? ?? 80 f1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

