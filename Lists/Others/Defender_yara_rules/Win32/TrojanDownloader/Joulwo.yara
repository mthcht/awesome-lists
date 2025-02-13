rule TrojanDownloader_Win32_Joulwo_A_2147602316_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Joulwo.A"
        threat_id = "2147602316"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Joulwo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {53 68 00 00 00 02 6a 03 53 6a 01 68 00 00 00 80 50 ff 15 ?? ?? ?? 10 6a 02 8b f8 53 68 38 ff ff ff 57 ff 15 ?? ?? ?? 10 8d 45 e8 53 50 8d 85 d8 fe ff ff 68 c8 00 00 00 50 57}  //weight: 3, accuracy: Low
        $x_2_2 = {68 98 3a 00 00 56 6a 02 e8 ?? ?? ff ff 85 c0 56 74 ?? 68 00 01 00 00 ff 15}  //weight: 2, accuracy: Low
        $x_3_3 = {68 00 28 00 00 50 ff 74 24 38 ff 15 ?? ?? ?? 10 83 f8 01 0f 85 ?? ?? ?? 00 bd 70 5a 00 10 55 e8 ?? ?? ?? 00 59 b9 fb 27 00 00 2b}  //weight: 3, accuracy: Low
        $x_1_4 = "[Password]" ascii //weight: 1
        $x_1_5 = "[Backup]" ascii //weight: 1
        $x_1_6 = "[server1]" ascii //weight: 1
        $x_1_7 = "[Primary]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

