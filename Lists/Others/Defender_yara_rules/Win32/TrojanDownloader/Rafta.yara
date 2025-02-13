rule TrojanDownloader_Win32_Rafta_A_2147656901_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rafta.A"
        threat_id = "2147656901"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rafta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c0 8a 8b f0 9e 00 00 8b bd ?? ?? ?? ?? 30 0c 38 40 3d 00 10 00 00 72 f5 8a 0f}  //weight: 10, accuracy: Low
        $x_1_2 = {80 78 02 0e 75 ?? c6 46 02 0e c6 46 03 02 39 bb a0 97 00 00 75 ?? c6 46 03 03}  //weight: 1, accuracy: Low
        $x_1_3 = {80 78 02 0a 75 ?? c6 46 02 0a c6 46 03 02 83 bb a0 97 00 00 01 75 ?? c6 46 03 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

