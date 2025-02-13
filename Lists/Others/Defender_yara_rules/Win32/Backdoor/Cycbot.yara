rule Backdoor_Win32_Cycbot_B_2147789622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Cycbot.B"
        threat_id = "2147789622"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Cycbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "/gbot/t.php?q=%s" ascii //weight: 2
        $x_2_2 = "type=%s&system=%s&id=%s&status=%s" ascii //weight: 2
        $x_2_3 = {2f 63 67 69 2d 62 69 6e 2f 63 79 63 6c 65 5f 72 65 70 6f 72 74 [0-2] 2e 63 67 69}  //weight: 2, accuracy: Low
        $x_2_4 = "%s/gbot/sc.cgi?id=%s&c=%d" ascii //weight: 2
        $x_1_5 = "PING_LS_TM_%d" ascii //weight: 1
        $x_1_6 = {73 74 6f 72 2e 63 66 67 00}  //weight: 1, accuracy: High
        $x_1_7 = "_LAST_TIME_FAIL_CONNECT_MAIN_SERVER" ascii //weight: 1
        $x_1_8 = "SEND_INSTALL_REPORT" ascii //weight: 1
        $x_2_9 = "User-Agent: gbot/" ascii //weight: 2
        $x_2_10 = "User-Agent: iamx/" ascii //weight: 2
        $x_2_11 = "id=%s&hwid=%s&c=%d&ver=" ascii //weight: 2
        $x_1_12 = {50 41 52 41 4d 5f 50 52 4f 58 59 5f 50 4f 52 54 (5f 4e 55 4d 42|4e)}  //weight: 1, accuracy: Low
        $x_1_13 = "images/im133.jpg" ascii //weight: 1
        $x_1_14 = "images/3521.jpg" ascii //weight: 1
        $x_2_15 = {2f 67 2f 74 2e 70 68 70 3f 71 3d 25 73 00}  //weight: 2, accuracy: High
        $x_1_16 = "hwid=%s&id=%s" ascii //weight: 1
        $x_1_17 = "&wd=%d&av=%s" ascii //weight: 1
        $x_1_18 = {49 4e 53 54 5f 52 45 50 4f 52 54 5f 54 4d 00}  //weight: 1, accuracy: High
        $x_1_19 = {4c 53 5f 50 49 4e 47 5f 54 4d 00}  //weight: 1, accuracy: High
        $x_2_20 = {68 77 69 64 3d 25 73 26 63 3d 25 64 26 ?? ?? ?? 3d 30 26 76 65 72 3d}  //weight: 2, accuracy: Low
        $x_1_21 = "t=%s&hrs=%d&q=%s&s=%d" ascii //weight: 1
        $x_3_22 = {43 81 fb d0 07 00 00 72 e7 eb ?? 81 7c 24 0c dc 05 00 00 73 06 ff 44 24 0c eb ?? 50 e8}  //weight: 3, accuracy: Low
        $x_2_23 = {50 41 52 41 4d 5f 4c 49 53 54 45 4e 5f 50 4f 52 54 00}  //weight: 2, accuracy: High
        $x_1_24 = {5c 67 62 5f 25 64 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_2_25 = {8b 45 f4 80 7d ff 06 fe 45 ff 8d 34 02 8a 06 72 04 c6 45 ff 01 0f b6 4d ff d2 c0 42 88 06 3b 55 f8 72 dd}  //weight: 2, accuracy: High
        $x_3_26 = {99 b9 2c 01 00 00 f7 f9 (8b fb 8b f2|89 9d ?? ?? ff ff 8b fa) c8 00 00 00 74 ?? e8 ?? ?? ?? ?? 25 3f 00 00 80 79}  //weight: 3, accuracy: Low
        $x_3_27 = {b8 28 01 00 00 39 06 75 ?? 8b 4d ?? 3b cb 74 08 3b 8e 08 01 00 00 75 ?? 8b 8d ?? ?? ff ff 3b cb 74 08 8b 96 0c 01 00 00 89 11 39 5d ?? 75}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Cycbot_C_2147792403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Cycbot.C"
        threat_id = "2147792403"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Cycbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {84 c0 75 13 68 58 1b 00 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15}  //weight: 3, accuracy: Low
        $x_3_2 = "type=%s&system=%s&id=%s&status=%s" ascii //weight: 3
        $x_1_3 = "nil|%s|nil" ascii //weight: 1
        $x_1_4 = "%s?tq=%s" ascii //weight: 1
        $x_1_5 = "at %d:%d \"%s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Cycbot_A_2147792444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Cycbot.A"
        threat_id = "2147792444"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Cycbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&hwid=A590474043D7B4753D1F" ascii //weight: 1
        $x_1_2 = "http://qimufefah.cn/gbot" ascii //weight: 1
        $x_1_3 = {5c 67 62 5f 25 64 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {40 65 63 68 6f 20 6f 66 66 0d 0a 3a 61 0d 0a 64 65 6c 20 22 25 73 22 0d 0a 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 61 0d 0a 64 65 6c 20 25 25 30 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_5 = {c6 45 ac 56 88 5d ad c6 45 ae 53 88 5d af c6 45 b0 5f 88 5d b1 c6 45 b2 56 88 5d b3 c6 45 b4 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

