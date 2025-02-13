rule TrojanDownloader_Win32_Sonide_A_2147651685_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sonide.A"
        threat_id = "2147651685"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sonide"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3c 4e 7c 04 3c 5a 7e 08 3c 6d 7c 08 3c 7a 7f 04 2c 0d 88 ?? ?? 80 ?? 00 75}  //weight: 2, accuracy: Low
        $x_2_2 = {3c 41 7c 04 3c 4d 7e 08 3c 61 7c ?? 3c 6d 7f ?? 04 0d eb}  //weight: 2, accuracy: Low
        $x_1_3 = "Zbmvyyn/4.0 (pbzcngvoyr; ZFVR " ascii //weight: 1
        $x_1_4 = {50 4f 53 54 00 00 00 00 25 73}  //weight: 1, accuracy: High
        $x_1_5 = {2f 66 62 63 75 76 6e 2f 76 61 73 62 ?? ?? 2e 63 75 63}  //weight: 1, accuracy: Low
        $x_1_6 = {76 72 6b 63 79 62 65 72 2e 72 6b 72 00}  //weight: 1, accuracy: High
        $x_1_7 = {73 76 65 72 73 62 6b 2e 72 6b 72 00}  //weight: 1, accuracy: High
        $x_1_8 = {4a 76 61 71 62 6a 66 5c 50 68 65 65 72 61 67 49 72 65 66 76 62 61 5c 45 68 61 00}  //weight: 1, accuracy: High
        $x_1_9 = {34 63 88 46 13 8d 46 15 5b 8d a4 24 00 00 00 00 0f b6 50 fb 30 50 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

