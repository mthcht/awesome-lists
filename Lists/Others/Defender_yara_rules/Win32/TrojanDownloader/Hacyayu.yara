rule TrojanDownloader_Win32_Hacyayu_A_2147653439_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hacyayu.A"
        threat_id = "2147653439"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hacyayu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {88 1f 0f b6 7d ff 0f b6 db 03 fb 8a 5d fe 81 e7 ff 00 00 00 32 1c 07 fe c1}  //weight: 2, accuracy: High
        $x_2_2 = {83 7c 24 2c 14 72 16 68 ?? ?? ?? ?? 56 ff 15}  //weight: 2, accuracy: Low
        $x_1_3 = {39 7d f8 74 06 8b 45 f8 31 45 fc}  //weight: 1, accuracy: High
        $x_1_4 = "hid=%s&file=%d" ascii //weight: 1
        $x_1_5 = {26 73 74 61 74 75 73 3d (67 6f|6e 6f 66 69)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

