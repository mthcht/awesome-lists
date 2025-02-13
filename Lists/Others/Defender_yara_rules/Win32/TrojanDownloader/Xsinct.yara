rule TrojanDownloader_Win32_Xsinct_2147620891_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Xsinct"
        threat_id = "2147620891"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Xsinct"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 ec 08 02 00 00 8d 44 24 00 68 04 01 00 00 50 6a 00 ff 15 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 48 75 31 8d 4c 24 00 68 ?? ?? ?? ?? 51 e8}  //weight: 10, accuracy: Low
        $x_1_2 = {73 69 6e 78 33 32 2e 64 6c 6c 00 42 65 49 6e 73 65 72 74 65 64}  //weight: 1, accuracy: High
        $x_1_3 = {49 6e 73 74 61 6c 6c 48 6f 6f 6b 00 4d 61 69 6e 4d 6f 6e 69 74 6f 72}  //weight: 1, accuracy: High
        $x_1_4 = {2e 00 61 00 73 00 70 00 3f 00 6d 00 61 00 63 00 69 00 64 00 3d 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {2f 00 6e 00 65 00 77 00 2e 00 65 00 78 00 65 00 00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

