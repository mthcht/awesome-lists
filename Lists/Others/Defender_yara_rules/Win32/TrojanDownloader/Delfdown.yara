rule TrojanDownloader_Win32_Delfdown_2147628120_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delfdown"
        threat_id = "2147628120"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfdown"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {ff ff ff ff 1e 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 79 73 74 65 6d 33 32 5c 53 74 6f 72 6d 32 2e 65 78 65}  //weight: 5, accuracy: High
        $x_5_2 = {44 3a 5c 42 72 6f 77 73 65 72 73 2e 65 78 65 00 63 6d 64 20 2f 63 20 61 74 74 72 69 62 20 2b 68 20 2b 72 20 2b 73 20 44 3a 5c 42 72 6f 77 73 65 72 73 2e 65 78 65}  //weight: 5, accuracy: High
        $x_1_3 = {ff ff ff ff 15 00 00 00 68 74 74 70 3a 2f 2f 64 2e 6c 61 69 79 69 62 61 2e 63 6f 6d 2f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

