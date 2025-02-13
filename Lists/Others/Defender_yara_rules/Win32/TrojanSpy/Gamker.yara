rule TrojanSpy_Win32_Gamker_A_2147684154_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Gamker.A"
        threat_id = "2147684154"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ollydbg.exe" ascii //weight: 1
        $x_1_2 = ":Zone.Identifier" ascii //weight: 1
        $x_10_3 = {88 1f 8b 7d ec 88 5d ff 0f b6 5d 0b 88 1f 0f b6 5d 0b 0f b6 7d ff 03 fb 8a 5d fe 81 e7 ff 00 00 00 32 1c 07 fe c1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Gamker_A_2147684154_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Gamker.A"
        threat_id = "2147684154"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "botid=%s&username=%s&ver=" ascii //weight: 1
        $x_1_2 = {81 79 fc ba ba ba ab 75 0e 81 3c 0a ba ba ba ab 75 05 b0 01}  //weight: 1, accuracy: High
        $x_1_3 = {21 64 6f 77 6e 5f 65 78 65 63 20 28 5c 53 2b 29 20 28 5c 53 2b 29 00}  //weight: 1, accuracy: High
        $x_1_4 = {21 6b 6e 6f 63 6b 5f 74 69 6d 65 20 28 5c 53 2b 29 20 28 5c 53 2b 29 00}  //weight: 1, accuracy: High
        $x_1_5 = {21 73 79 73 5f 69 6e 69 74 20 28 5c 53 2b 29 3a 28 5c 53 2b 29 20 28 5c 53 2b 29 00}  //weight: 1, accuracy: High
        $x_1_6 = "Referer: http://www.facebook.com" ascii //weight: 1
        $x_1_7 = {45 78 65 63 43 6d 64 44 65 73 6b 00}  //weight: 1, accuracy: High
        $x_1_8 = {41 00 44 00 4d 00 49 00 4e 00 00 00 55 00 53 00 45 00 52 00 00 00 00 00 25 77 73 5c 25 77 73 5c 25 77 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Gamker_A_2147684154_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Gamker.A"
        threat_id = "2147684154"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c6 85 cf fe ff ff 66 c6 85 d0 fe ff ff 74 c6 85 d1 fe ff ff 53 c6 85 d2 fe ff ff 53 c6 85 d3 fe ff ff 35 c6 85 d4 fe ff ff 35 c6 85 d5 fe ff ff 31 c6 85 d6 fe ff ff 31 c6 85 d7 fe ff ff 47 c6 85 d8 fe ff ff 61 c6 85 d9 fe ff ff 74 c6 85 da fe ff ff 65}  //weight: 10, accuracy: High
        $x_10_2 = {c6 85 d7 fe ff ff 66 c6 85 d8 fe ff ff 74 c6 85 d9 fe ff ff 53 c6 85 da fe ff ff 53 c6 85 db fe ff ff 35 c6 85 dc fe ff ff 35 c6 85 dd fe ff ff 31 c6 85 de fe ff ff 31 c6 85 df fe ff ff 47 c6 85 e0 fe ff ff 61 c6 85 e1 fe ff ff 74 c6 85 e2 fe ff ff 65}  //weight: 10, accuracy: High
        $x_10_3 = {4d 69 63 72 c7 45 ?? 6f 73 6f 66 c7 45 ?? 74 53 53 35 c7 45 ?? 35 31 31 47 c7 45 ?? 61 74 65 00}  //weight: 10, accuracy: Low
        $x_1_4 = {65 79 75 69 6f 61 00 00 71 77 72 74 70 73 64 66 67 68 6a 6b 6c 7a 78 63 76 62 6e 6d 5f 00}  //weight: 1, accuracy: High
        $x_1_5 = {33 d2 4f f7 f7 8a 54 15 d4 8b 45 fc 8b 4d 08 88 14 08 80 fa 5f 0f 84 05 ff ff ff 40 89 45 fc 3b 45 0c 0f 8c e8 fd ff ff}  //weight: 1, accuracy: High
        $x_1_6 = {eb 05 8b ff 8b 4d f4 0f b6 0c 31 88 4d fe 8a 88 00 01 00 00 0f b6 f9 0f b6 14 07 03 f8 88 55 0b 8a 90 01 01 00 00 02 55 0b}  //weight: 1, accuracy: Low
        $x_1_7 = {83 f9 18 72 5d 8b 1e 81 fb 41 50 33 32 75 53 8b 5e 04 83 fb 18 72 4b 29 d9 72 47 39 4e 08 77 42}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Gamker_A_2147684213_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Gamker.A!dll"
        threat_id = "2147684213"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamker"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 6f 74 69 64 3d 25 73 26 76 65 72 3d [0-8] 26 75 70 3d 25 75 26 6f 73 3d 25 30 33 75 26 6c 74 69 6d 65 3d 25 73 25 64 26 74 6f 6b 65 6e 3d 25 64 26 63 6e 3d 74 65 73 74 78 26 61 76 3d 25 73}  //weight: 1, accuracy: Low
        $x_1_2 = "BUH|BANK|ACCOUNT|CASH|KASSA|DIREK|FINAN|OPER|FINOTDEL|DIRECT|ROSPIL" ascii //weight: 1
        $x_1_3 = "iexplore.exe|opera.exe|firefox.exe|chrome.exe|maxthon.exe|java.exe" ascii //weight: 1
        $x_1_4 = {2f 67 69 74 68 75 62 2e 70 68 70 00 5f 30 78 25 30 38 78 00 2e 74 6d 70}  //weight: 1, accuracy: High
        $x_1_5 = {0f b6 5d 0f 88 1f 0f b6 5d 0f 0f b6 7d 0b 03 fb 8a 5d ff 81 e7 ff 00 00 00 32 1c 07 fe c1 88 88 00 01 00 00 88 90 01 01 00 00 88 1e 46 ff 4d f8 75 90}  //weight: 1, accuracy: Low
        $x_1_6 = {75 2d b8 02 00 00 00 e8 dc 46 00 00 85 c0 74 15 33 c9 80 38 31 8b f0 0f 94 c1 89 0d 94 c0 05 10 e8 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 83 3d ?? ?? ?? ?? ?? ?? 75 6c 85 db 75 4f 33 f6 39 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Gamker_B_2147686353_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Gamker.B"
        threat_id = "2147686353"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!down_exec (\\S+) (\\S+)" ascii //weight: 1
        $x_1_2 = "SYSTEM!%s!" ascii //weight: 1
        $x_1_3 = "botid=%s&username=%s&ver=1.0&up=%u&os=%03u&token=%d&cn=" ascii //weight: 1
        $x_1_4 = "netsh firewall set service type = REMOTEDESKTOP mode = ENABLE" ascii //weight: 1
        $x_1_5 = ":Zone.Identifier" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

