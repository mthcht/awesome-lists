rule TrojanDownloader_Win32_Brysyler_A_2147638732_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Brysyler.A"
        threat_id = "2147638732"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Brysyler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {f3 ab 8a 06 2c ?? 6a 01 88 44 24 ?? 8d 44 24 ?? 8d 4c 24 ?? 50 51 e8 ?? ?? ?? ?? 8a 46 ?? 83 c4 0c 46 84 c0 75 de}  //weight: 3, accuracy: Low
        $x_1_2 = {3c 42 52 3e [0-10] 3d 3d 63 68 [0-10] 63 68 3d 3d}  //weight: 1, accuracy: Low
        $x_1_3 = {75 70 67 72 [0-5] 2e 68 74 6d [0-21] 77 77 77 2e 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\winsys32.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

