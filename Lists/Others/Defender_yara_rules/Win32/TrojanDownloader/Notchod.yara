rule TrojanDownloader_Win32_Notchod_A_2147599718_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Notchod.A"
        threat_id = "2147599718"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Notchod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 30 40 8a 10 32 f2 88 33 43 40 41 3b 4d 0c 72 ef}  //weight: 1, accuracy: High
        $x_1_2 = {68 fa 00 00 00 ff 15 ?? ?? ?? ?? 68 05 01 00 00 6a 40 ff 15 ?? ?? ?? ?? 89 45 fc 68 04 01 00 00 ff 75 fc 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 75 fc 6a 00 6a 00 ff 75 fc ff 15 ?? ?? ?? ?? 6a 00 6a 00 ff 75 fc ff 75 08 6a 00 ff ?? ?? ?? ?? ?? ff 45 f8 0b c0 74 08 83 7d f8 04 73 02 eb a2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

