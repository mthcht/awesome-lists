rule TrojanDownloader_Win32_MapsGory_A_2147725307_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/MapsGory.A!bit"
        threat_id = "2147725307"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "MapsGory"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 ec 73 55 dc 05 8d 4d ec 51 e8 ?? ?? ?? ff a3 ?? ?? ?? 00 8b 15 ?? ?? ?? 00 52 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f 00 2f 6c 6f 61 64 65 72 2f 63 6f 6d 65 74 61 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 61 62 61 6e 64 6f 6e 20 61 62 69 6c 69 74 79 20 61 62 6c 65 20 61 62 6f 75 74 20 61 62 6f 76 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

