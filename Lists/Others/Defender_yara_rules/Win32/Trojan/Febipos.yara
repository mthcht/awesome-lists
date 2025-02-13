rule Trojan_Win32_Febipos_A_2147682568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Febipos.gen!A"
        threat_id = "2147682568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Febipos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 73 5c 31 2e 63 72 78 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 73 5c 74 65 6d 70 2e 63 72 78 00}  //weight: 1, accuracy: High
        $x_1_3 = "key\": \"MIGfMA0GCSqGSIb3DQEBA" ascii //weight: 1
        $x_1_4 = {66 69 72 65 66 6f 78 2e 65 78 65 00 46 61 63 65 62 6f 6f 6b 20 55 70 64 61 74 65}  //weight: 1, accuracy: High
        $x_1_5 = "@facebook.com.xpi" ascii //weight: 1
        $x_1_6 = {53 74 61 72 74 3d 61 75 74 6f 0a 00 53 74 61 72 74 4e 6f 77 3d 74 72 75 65 0a 00}  //weight: 1, accuracy: High
        $x_2_7 = {74 04 c6 45 e2 01 8b 45 e8 8d 14 85 00 00 00 00 8b 45 d4 01 d0 c7}  //weight: 2, accuracy: High
        $x_2_8 = {74 04 c6 45 e2 01 8a 45 e2 83 f0 01 84 c0 74 7e 8b 85 ?? ?? ff ff 89 04 24 e8 ?? ?? ?? ?? 89 45 e4 eb 01 90 8b 85 ?? ?? ff ff 89 04 24 e8}  //weight: 2, accuracy: Low
        $x_2_9 = {3b 45 e4 7c cf eb 08 83 7d ?? 65 75 a6 eb 02 eb a2 8b 45 f4 40 89 45}  //weight: 2, accuracy: Low
        $x_2_10 = {89 45 d8 eb 58 8a 45 f3 83 f0 01 84 c0 74 15 8b 45 dc 89 44 24 04 8d 85 d8 f5 ff ff 89 04 24 e8}  //weight: 2, accuracy: High
        $x_2_11 = {7c c2 eb 08 83 7d ?? 65 75 99 eb 02 eb 95 8a 45 e3 83 f0 01 84 c0 0f 84 7e 02 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Febipos_B_2147684042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Febipos.B"
        threat_id = "2147684042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Febipos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 73 5c 57 53 65 72 76 69 63 65 2e 64 6c 6c 00 25 73 5c 72 65 67 73 76 72 33 32 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = "DisableAddonLoadTimePerformanceNotifications" ascii //weight: 1
        $x_1_3 = "IgnoreFrameApprovalCheck" ascii //weight: 1
        $x_1_4 = "@facebook.com.xpi" ascii //weight: 1
        $x_2_5 = "://pubupl.com/updates/" ascii //weight: 2
        $x_2_6 = "sm5r/t0oa/g8llkaie.xml" ascii //weight: 2
        $x_2_7 = {3c 09 75 e7 0f b6 03 3c 20 75 73 83 c3 01 0f b6 03 3c 09 74 f6 3c 20 74 f2 f6 45 d0 01 be 0a 00 00 00 74 04 0f b7 75 d4 c7 04 24 00 00 00 00 e8 ?? ?? ?? ?? 83 ec 04 89 74 24 0c 89 5c 24 08 c7 44 24 04 00 00 00 00 89 04 24 e8}  //weight: 2, accuracy: Low
        $x_1_8 = "\"scripts\": [ \"ante.js\"," ascii //weight: 1
        $x_1_9 = "\"scripts\": [ \"supprimer.js\"," ascii //weight: 1
        $x_1_10 = "\"install_time\": \"13006874669995739\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Febipos_B_2147684055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Febipos.B!dll"
        threat_id = "2147684055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Febipos"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 5f 04 75 19 c7 45 fc ff ff ff ff 39 75 e4 0f 82 b2 01 00 00 8b 4d d0 51 e9 a1 01 00 00 c6 45 fc 01 8b 47 04 8b 10 8b 52 48 8d 4d bc 51 50 ff d2 3b c3 74 0f c7}  //weight: 1, accuracy: High
        $x_1_2 = "{3543619C-D563-43f7-95EA-4DA7E1CC396A}" wide //weight: 1
        $x_1_3 = "MicrosoftSecurityPlugin" wide //weight: 1
        $x_2_4 = "https://supbr.info/sqlvarbr.php" ascii //weight: 2
        $x_2_5 = {89 5d fc 8b 45 d0 be 08 00 00 00 39 75 e4 73 03 8d 45 d0 68 ?? ?? ?? ?? 68 78 dc 00 10 50 e8 ?? ?? ?? ?? 83 c4 0c 89 5d cc 39 5d e0 75 12 be 13 00 00 00 8d 45 d0}  //weight: 2, accuracy: Low
        $x_1_6 = "beginIt();" ascii //weight: 1
        $x_1_7 = {ff d3 85 c0 0f 85 7e 00 00 00 8d 85 fc f7 ff ff 8d 50 02 8d 49 00 66 8b 08 83 c0 02 66 85 c9 75 f5 2b c2 8b 95 f8 f7 ff ff d1 f8 8d 44 00 02 50 8d 8d fc f7 ff ff 51 6a 01 6a 00 6a 00 52 ff d6 8b 85 f8 f7 ff ff 6a 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Febipos_C_2147684113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Febipos.C"
        threat_id = "2147684113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Febipos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 7b 7d 00 63 6f 75 6e 74 72 79 5f 63 6f 64 65 00 42 52}  //weight: 1, accuracy: High
        $x_1_2 = "Facebook Update" ascii //weight: 1
        $x_1_3 = "0Bz1tdMB1w6ydN1BObFRSM09vUU0&amp;export=download" ascii //weight: 1
        $x_1_4 = "%s\\fbvideoplugin.exe" ascii //weight: 1
        $x_2_5 = {8d 85 c4 e9 ff ff 66 c7 00 58 58 c6 40 02 00 8d 85 d4 fd ff ff 89 04 24 e8 7b 0a 00 00 c7 44 24 04 ?? ?? ?? ?? 8d 85 c4 e9 ff ff 89 04 24 e8 ?? ?? ?? ?? 85 c0 0f 85 0a 02 00 00 8b 45 dc 89 44 24 08 c7 44 24 04 ?? ?? ?? ?? 8d 85 d4 fd ff ff 89 04 24 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

