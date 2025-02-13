rule TrojanDownloader_Win32_Femad_2147572876_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Femad"
        threat_id = "2147572876"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Femad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "gofuckyourself.com" ascii //weight: 2
        $x_2_2 = "crutop.nu" ascii //weight: 2
        $x_2_3 = "explorer:Trojan Horse ALERT!" ascii //weight: 2
        $x_2_4 = ":Spyware Trojan Horse ALERT!" ascii //weight: 2
        $x_2_5 = "if exist %1 goto start" ascii //weight: 2
        $x_2_6 = ".seek-all.com/search.php?" ascii //weight: 2
        $x_1_7 = ".adaware.cc" ascii //weight: 1
        $x_1_8 = "dialerschutz.de" ascii //weight: 1
        $x_1_9 = "webmasterworld.com" ascii //weight: 1
        $x_1_10 = ".ad-ware.cc" ascii //weight: 1
        $x_1_11 = ".cexx.org" ascii //weight: 1
        $x_2_12 = {47 45 54 00 ff ff ff ff ?? ?? 40 00 ?? ?? 40 00 65 78 70 6c 6f 72 65 72 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_1_13 = {47 45 54 00 4d 6f 7a 69 6c 6c 61 2f 34 2e 30}  //weight: 1, accuracy: High
        $x_1_14 = {2e 65 78 65 00 00 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: High
        $x_2_15 = {c6 47 02 74 c6 47 04 3a c6 47 05 2f c6 07 68}  //weight: 2, accuracy: High
        $x_3_16 = {89 5d d4 66 81 3b 4d 5a 0f 85 ?? 00 00 00 8b 43 3c 03 c3 89 45 d0 81 38 50 45 00 00 75}  //weight: 3, accuracy: Low
        $x_2_17 = {8a 02 56 57 2c ?? 0f b6 f8 57 8d 42 01 50 8b f1 56 6a 01 52 e8}  //weight: 2, accuracy: Low
        $x_2_18 = {57 8b 7c 24 0c 0f b6 f0 56 8d 41 01 50 57 6a 01 51 e8}  //weight: 2, accuracy: High
        $x_3_19 = {1b 8a 19 88 18 88 11 8a ca 02 08 0f b6 c1 8a 84 05}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

