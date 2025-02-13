rule TrojanDownloader_Win32_Genuyf_A_2147627076_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Genuyf.A"
        threat_id = "2147627076"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Genuyf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 73 65 72 33 32 2e 64 6c 6c 00 4c 6f 61 64 52 65 6d 6f 74 65 46 6f 6e 74 73 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 00 68 74 74 70 3a 2f 2f 63 6e 2e 63 6f 6d 2e 66 65 6e 67 79 75 6e 66 7a 2e 63 6f 6d 2e 63 6e 2f 69 6d 61 67 65 73 2f 69 6d 61 67 65 73 2f 64 6f 77 6e 2e 74 78 74}  //weight: 1, accuracy: High
        $x_1_2 = {81 c4 e8 fd ff ff 33 c0 89 ?? ?? 6a 00 6a 00 6a 00 6a 00 68 ?? ?? 40 00 e8 ?? ?? 00 00 0b c0 0f 84 ?? 00 00 00 89 ?? ?? 6a 04 ff 75 ?? 6a 02 ff 75 ?? e8 ?? ?? 00 00 6a 04 ff 75 ?? 6a 06 ff 75 ?? e8 ?? ?? 00 00 6a 00 68 00 00 20 00 6a 00 6a 00 ff 75 ?? ff 75 ?? e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

