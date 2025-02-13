rule TrojanDownloader_Win32_Utilmalm_A_2147718299_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Utilmalm.A!bit"
        threat_id = "2147718299"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Utilmalm"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 5a 1a 83 ?? ?? 03 5a 16 e2 f5 e9}  //weight: 2, accuracy: Low
        $x_2_2 = {73 16 8b 55 f8 03 55 fc 0f b6 02 83 f0 2b 8b 4d f8 03 4d fc 88 01 eb}  //weight: 2, accuracy: High
        $x_1_3 = {50 8b 4d 08 8b 91 ?? ?? ?? ?? ff d2}  //weight: 1, accuracy: Low
        $x_1_4 = {50 8b 4d fc 51 8b 55 08 8b 82 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_5 = {50 e8 00 00 00 00 58 05 ff 00 00 00 05 0e 01 00 00 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

