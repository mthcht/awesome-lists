rule TrojanDownloader_Win32_Colste_A_2147688292_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Colste.A"
        threat_id = "2147688292"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Colste"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 8b 45 08 80 38 00 74 0b 8b c8 80 31 ?? 41 80 39 00 75 f7 5d c3}  //weight: 10, accuracy: Low
        $x_5_2 = {68 50 93 08 00 57 ff ?? ?? 53 e8 ?? ?? ?? ?? 68 50 93 08 00 ff ?? ?? 57 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 e8}  //weight: 5, accuracy: Low
        $x_5_3 = {68 b8 88 00 00 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15}  //weight: 5, accuracy: Low
        $x_1_4 = {5c 78 77 69 6e 6d 6f 6e 00 [0-32] 5c 77 69 6e 6d 6f 6e 36 34 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = "\\xpmwin32.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

