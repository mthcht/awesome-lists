rule TrojanDownloader_Win32_EyeStye_C_2147646689_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/EyeStye.C"
        threat_id = "2147646689"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 8d 50 01 8a 08 40 84 c9 75 f9 2b c2 56 8b f0 8d 46 01 57 50 e8 88 04 00 00 33 ff 59 c6 04 30 00 85 f6 7e 0f 8d 4c 1e ff 8a 11 88 14 07 47 49 3b fe 7c f5}  //weight: 1, accuracy: High
        $x_1_2 = {68 f4 01 00 00 ff d7 ff ?? ?? 8b ?? ?? 3b 05 ?? ?? ?? ?? 76 ?? c7 45 f4 ?? ?? ?? ?? c7 45 f8 ?? ?? ?? ?? c7 45 fc ?? ?? ?? ?? 33 ff 56 56 56 56 ff ?? ?? ?? 56 6a 05 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 24 84 c0 74}  //weight: 1, accuracy: Low
        $x_1_3 = {33 f6 59 56 56 56 56 85 c0 75 ?? 68 ?? ?? ?? ?? eb ?? 68 ?? ?? ?? ?? 56 6a 05 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_EyeStye_D_2147648958_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/EyeStye.D"
        threat_id = "2147648958"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeStye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {59 8b 0e 89 01 8b 06 83 38 00 74 cf}  //weight: 1, accuracy: High
        $x_1_2 = {03 f3 30 06 43 3b 5d 10 72 bc 8b 45 08}  //weight: 1, accuracy: High
        $x_1_3 = {77 61 69 74 63 6f 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

