rule TrojanDownloader_Win32_Rispere_2147602873_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rispere"
        threat_id = "2147602873"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rispere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 33 45 d0 0f bf d0 52 ff 15 ?? ?? ?? ?? 8b d0 8d 4d c8 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b d0 8d 4d d4 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {6b 70 ff fb 12 e7 0b ?? 00 04 00 23 44 ff 2a 31 74 ff 32 04 00 48 ff 44 ff 35 4c ff 00 0c 6b 70 ff f3 ff 00 c6 1c ?? ?? 00 07 f4 01 70 70 ff 1e ?? ?? 00 0b 6b 70 ff f4 01 a9 70 70 ff 00 0a 04 72 ff 64 6c}  //weight: 10, accuracy: Low
        $x_5_3 = {6b 56 ff f4 02 c6 1c 4c 00 00 19 1b 01 00 43 50 ff 04 50 ff 0b 02 00 04 00 fd e7 08 00 00 00 2f 50 ff 1e 70 00 00 0b 6b 56 ff f4 01 c6 1c 70 00 00 19}  //weight: 5, accuracy: High
        $x_5_4 = "la.546*9" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

