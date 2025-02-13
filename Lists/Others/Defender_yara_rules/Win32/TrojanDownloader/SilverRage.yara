rule TrojanDownloader_Win32_SilverRage_A_2147732043_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/SilverRage.A!dha"
        threat_id = "2147732043"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "SilverRage"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 65 7a 37 2f 2b 72 37 7a 75 7a 78 2f 66 76 74 37 64 38 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = {52 46 45 3a 25 30 38 78 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 46 45 3a 25 30 38 78 00}  //weight: 1, accuracy: High
        $x_1_4 = {43 50 45 3a 25 30 38 78 00}  //weight: 1, accuracy: High
        $x_1_5 = {79 38 7a 53 30 65 37 37 38 4d 33 71 37 50 76 2f 38 39 38 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = {79 38 7a 53 32 76 48 70 38 50 4c 78 2f 2f 72 4b 38 64 6a 33 38 76 76 66 00}  //weight: 1, accuracy: High
        $x_1_7 = {3f 69 64 3d 64 6e 36 37 38 00}  //weight: 1, accuracy: High
        $x_1_8 = {32 76 76 79 2b 2b 72 37 79 2b 7a 79 33 66 2f 39 39 76 76 62 38 4f 72 73 35 39 38 3d 00}  //weight: 1, accuracy: High
        $x_1_9 = {47 46 53 45 3a 25 30 38 78 00}  //weight: 1, accuracy: High
        $x_1_10 = {44 46 45 3a 25 30 38 78 00}  //weight: 1, accuracy: High
        $x_1_11 = {4c 41 45 3a 25 30 38 78 00}  //weight: 1, accuracy: High
        $x_1_12 = {25 73 64 2e 25 73 65 25 73 63 20 25 73 20 3e 20 25 73 20 32 3e 26 31 00}  //weight: 1, accuracy: High
        $x_1_13 = {20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 40 54 4d 50 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

