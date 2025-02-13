rule TrojanDownloader_Win32_Silvpat_A_2147687489_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Silvpat.A"
        threat_id = "2147687489"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Silvpat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3e e9 74 15 b9 ?? ?? ?? ?? 33 db ac 34 22 aa e2 fa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

