rule TrojanDownloader_Win32_Abovid_A_2147627889_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Abovid.A"
        threat_id = "2147627889"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Abovid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 00 00 00 68 74 74 70 3a 2f 2f 64 6f 77 6e 2e 6e 61 6d 65 70 69 63 73 2e 69 6e 66 6f 2f 69 6e 73 74 61 6c 6c 2e 70 68 70 3f 6e 61 6d 65 3d}  //weight: 1, accuracy: High
        $x_1_2 = {8b 83 04 03 00 00 89 58 74 c7 40 70 ?? ?? ?? ?? 89 58 7c c7 40 78 ?? ?? ?? ?? e8 ?? ?? ?? ?? ba ?? ?? ?? ?? 8b 83 f8 02 00 00 e8 ?? ?? ?? ?? 33 d2 8b 83 f8 02 00 00 8b 08 ff 51 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

