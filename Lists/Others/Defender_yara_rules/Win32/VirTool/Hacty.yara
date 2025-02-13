rule VirTool_Win32_Hacty_C_2147604851_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Hacty.gen!C"
        threat_id = "2147604851"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Hacty"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b c7 8d 50 01 8a 08 40 84 c9 75 f9 2b c2 89 45 2c 74 61 8b 43 3c d1 e8 50 57 ff 75 fc ff 15}  //weight: 5, accuracy: High
        $x_5_2 = {8b 4b 3c d1 e9 3b c1 74 10 81 c7 00 01 00 00 81 ff 08 3a 01 00 7c c6 eb 38 83 7d 24 00 74 13 3b 5d 1c 75 09 c7 45 30 06 00 00 80 eb 24}  //weight: 5, accuracy: High
        $x_5_3 = {83 26 00 eb 1f 8b 03 8b 4d 1c 2b c8 2b cb 03 4d 20 8d 34 18 8b c1 c1 e9 02 8b fb f3 a5 8b c8 83 e1 03 f3 a4 8b f3 03 1b 83 7d 24 00 0f 84 12}  //weight: 5, accuracy: High
        $x_5_4 = {8b 45 18 8b 40 04 6a 14 59 f7 f1 83 65 1c 00 85 c0 7e 7a 8d 48 ff 89 4d 20 8d 4b 14 89 4d 2c be}  //weight: 5, accuracy: High
        $x_5_5 = {8b 3e 85 ff 74 54 33 c9 8a 6b 08 8a 4b 09 3b cf 74 0d 83 c6 04 81}  //weight: 5, accuracy: High
        $x_5_6 = {7c e3 eb 3b 8b 4d 20 39 4d 1c 74 2f 8b 75 2c 8b c8 2b 4d 1c 8b fb 49 8d 0c 89 c1 e1 02 8b d1 c1 e9 02 f3 a5 8b ca 83 e1 03 48 ff 4d 20 ff 4d 1c}  //weight: 5, accuracy: High
        $x_5_7 = {85 c0 7c 65 83 7d 08 05 75 5f 8b 16 57 33 ff 85 d2 8b ce 74 4f 8d 0c 32 eb 4a be}  //weight: 5, accuracy: High
        $x_5_8 = {8b 16 85 d2 74 2d 39 51 44 75 19 85 ff 74 0d 8b 11 85 d2 74 04 01 17 eb 03 83 27 00 8b 11 85 d2 74 0f 03 ca 83 c6 04 81}  //weight: 5, accuracy: High
        $x_5_9 = {7c d1 eb 02 33 c9 85 c9 74 12 8b 11 85 d2 8b f9 74 04 03 ca eb 02 33 c9 85 c9 75 b2 5f}  //weight: 5, accuracy: High
        $x_2_10 = "ZFJ_ROOTKIT" ascii //weight: 2
        $x_1_11 = "ZwQueryDirectoryFile" ascii //weight: 1
        $x_1_12 = "ZwQuerySystemInformation" ascii //weight: 1
        $x_1_13 = "ZwDeviceIoControlFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((6 of ($x_5_*))) or
            (all of ($x*))
        )
}

