rule Trojan_Win32_Pterodo_G_2147730720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pterodo.G"
        threat_id = "2147730720"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pterodo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 4b 42 4a 80 30 60 60 61 80 30 72 53 31 db 5b 40 48 80 28 88 53 31 db 5b 80 30 f6 53 31 db 5b 80 00 95 90 80 28 7b 42 4a 80 00 40 43 4b 80 28 11 60 61 80 00 15}  //weight: 1, accuracy: High
        $x_1_2 = {2e 65 78 65 00 5c 00 6f 70 65 6e 00 5c 4d 69 72 61 2e 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pterodo_A_2147813538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pterodo.A!MSR"
        threat_id = "2147813538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pterodo"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "RunProgram=\"hidcon:cmd.exe /c ping 8.8.8.8" ascii //weight: 1
        $x_1_2 = {52 00 75 00 6e 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 3d 00 22 00 68 00 69 00 64 00 63 00 6f 00 6e 00 3a 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 2f 00 62 00 20 00 25 00 55 00 53 00 45 00 52 00 50 00 52 00 4f 00 46 00 49 00 4c 00 45 00 25 00 5c 00 5c 00 [0-16] 2e 00 76 00 62 00 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 2f 62 20 25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 5c [0-16] 2e 76 62 73}  //weight: 1, accuracy: Low
        $x_1_4 = "GUIMode=\"2\"" ascii //weight: 1
        $x_1_5 = "InstallPath=\"%TEMP%\"" ascii //weight: 1
        $x_1_6 = "SelfDelete=\"1\"" ascii //weight: 1
        $x_1_7 = "\"IE9uIEVycm9yIFJlc3VtZSBOZXh0DQogDQp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Pterodo_A_2147813538_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pterodo.A!MSR"
        threat_id = "2147813538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pterodo"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "RunProgram=\"hidcon:cmd.exe /c echo .>%TEMP%\\\\log.txt\"" ascii //weight: 1
        $x_1_2 = {52 00 75 00 6e 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 3d 00 22 00 68 00 69 00 64 00 63 00 6f 00 6e 00 3a 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 63 00 6f 00 70 00 79 00 20 00 2f 00 79 00 20 00 25 00 54 00 45 00 4d 00 50 00 25 00 5c 00 5c 00 [0-4] 2e 00 6c 00 6f 00 67 00 20 00 25 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 25 00 22 00}  //weight: 1, accuracy: Low
        $x_1_3 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 63 6d 64 2e 65 78 65 20 2f 63 20 63 6f 70 79 20 2f 79 20 25 54 45 4d 50 25 5c 5c [0-4] 2e 6c 6f 67 20 25 41 50 50 44 41 54 41 25 22}  //weight: 1, accuracy: Low
        $x_1_4 = {52 00 75 00 6e 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 3d 00 22 00 68 00 69 00 64 00 63 00 6f 00 6e 00 3a 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 63 00 6f 00 70 00 79 00 20 00 2f 00 79 00 20 00 25 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 25 00 5c 00 5c 00 [0-4] 2e 00 6c 00 6f 00 67 00 20 00 [0-4] 2e 00 6c 00 6f 00 67 00 2e 00 76 00 62 00 73 00 22 00}  //weight: 1, accuracy: Low
        $x_1_5 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 63 6d 64 2e 65 78 65 20 2f 63 20 63 6f 70 79 20 2f 79 20 25 41 50 50 44 41 54 41 25 5c 5c [0-4] 2e 6c 6f 67 20 [0-4] 2e 6c 6f 67 2e 76 62 73 22}  //weight: 1, accuracy: Low
        $x_1_6 = {52 00 75 00 6e 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 3d 00 22 00 68 00 69 00 64 00 63 00 6f 00 6e 00 3a 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 2f 00 62 00 20 00 25 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 25 00 5c 00 5c 00 [0-4] 2e 00 6c 00 6f 00 67 00 2e 00 76 00 62 00 73 00 22 00}  //weight: 1, accuracy: Low
        $x_1_7 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 2f 62 20 25 41 50 50 44 41 54 41 25 5c 5c [0-4] 2e 6c 6f 67 2e 76 62 73 22}  //weight: 1, accuracy: Low
        $x_1_8 = "GUIMode=\"2\"" ascii //weight: 1
        $x_1_9 = "InstallPath=\"%TEMP%\"" ascii //weight: 1
        $x_1_10 = "SelfDelete=\"1\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Pterodo_MA_2147814895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pterodo.MA!MTB"
        threat_id = "2147814895"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pterodo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e4 05 20 ?? ?? ?? ?? b6 10 8b 45 e4 83 c0 01 0f b6 80 ?? ?? ?? ?? 31 c2 8b 45 e4 05 ?? ?? ?? ?? 88 10 83 45 e4 01 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 95 18 fa ff ff 89 54 24 24 8d 95 28 fa ff ff 89 54 24 20 c7 44 24 1c 00 00 00 00 c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 89 44 24 04 c7 04 24 00 00 00 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pterodo_AG1_2147815421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pterodo.AG1!MSR"
        threat_id = "2147815421"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pterodo"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 00 75 00 6e 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 3d 00 22 00 68 00 69 00 64 00 63 00 6f 00 6e 00 3a 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 63 00 6f 00 70 00 79 00 20 00 2f 00 79 00 20 00 25 00 54 00 45 00 4d 00 50 00 25 00 5c 00 5c 00 [0-5] 2e 00 6c 00 6f 00 67 00 20 00 25 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 25 00 22 00}  //weight: 1, accuracy: Low
        $x_1_2 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 63 6d 64 2e 65 78 65 20 2f 63 20 63 6f 70 79 20 2f 79 20 25 54 45 4d 50 25 5c 5c [0-5] 2e 6c 6f 67 20 25 41 50 50 44 41 54 41 25 22}  //weight: 1, accuracy: Low
        $x_1_3 = "RunProgram=\"hidcon:cmd.exe /c ping 8.8.8.8" ascii //weight: 1
        $x_1_4 = {52 00 75 00 6e 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 3d 00 22 00 68 00 69 00 64 00 63 00 6f 00 6e 00 3a 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 72 00 65 00 6e 00 61 00 6d 00 65 00 20 00 25 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 25 00 5c 00 5c 00 [0-5] 2e 00 6c 00 6f 00 67 00 20 00 [0-5] 2e 00 6c 00 6f 00 67 00 2e 00 76 00 62 00 73 00 22 00}  //weight: 1, accuracy: Low
        $x_1_5 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 63 6d 64 2e 65 78 65 20 2f 63 20 72 65 6e 61 6d 65 20 25 41 50 50 44 41 54 41 25 5c 5c [0-5] 2e 6c 6f 67 20 [0-5] 2e 6c 6f 67 2e 76 62 73 22}  //weight: 1, accuracy: Low
        $x_1_6 = {52 00 75 00 6e 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 3d 00 22 00 68 00 69 00 64 00 63 00 6f 00 6e 00 3a 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 2f 00 62 00 20 00 25 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 25 00 5c 00 5c 00 [0-5] 2e 00 6c 00 6f 00 67 00 2e 00 76 00 62 00 73 00 22 00}  //weight: 1, accuracy: Low
        $x_1_7 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 2f 62 20 25 41 50 50 44 41 54 41 25 5c 5c [0-5] 2e 6c 6f 67 2e 76 62 73 22}  //weight: 1, accuracy: Low
        $x_1_8 = {52 00 75 00 6e 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 3d 00 22 00 68 00 69 00 64 00 63 00 6f 00 6e 00 3a 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 64 00 65 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 71 00 20 00 25 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 25 00 5c 00 5c 00 [0-5] 2e 00 6c 00 6f 00 67 00 2e 00 76 00 62 00 73 00 22 00}  //weight: 1, accuracy: Low
        $x_1_9 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 63 6d 64 2e 65 78 65 20 2f 63 20 64 65 6c 20 2f 66 20 2f 71 20 25 41 50 50 44 41 54 41 25 5c 5c [0-5] 2e 6c 6f 67 2e 76 62 73 22}  //weight: 1, accuracy: Low
        $x_1_10 = "GUIMode=\"2\"" ascii //weight: 1
        $x_1_11 = "InstallPath=\"%TEMP%\"" ascii //weight: 1
        $x_1_12 = "SelfDelete=\"1\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Win32_Pterodo_AG2_2147815422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pterodo.AG2!MSR"
        threat_id = "2147815422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pterodo"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 00 75 00 6e 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 3d 00 22 00 68 00 69 00 64 00 63 00 6f 00 6e 00 3a 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 63 00 6f 00 70 00 79 00 20 00 2f 00 79 00 20 00 25 00 54 00 45 00 4d 00 50 00 25 00 5c 00 5c 00 [0-5] 2e 00 6c 00 6f 00 67 00 20 00 25 00 55 00 53 00 45 00 52 00 50 00 52 00 4f 00 46 00 49 00 4c 00 45 00 25 00 5c 00 5c 00 [0-5] 2e 00 6c 00 6f 00 67 00 2e 00 6c 00 6f 00 67 00 22 00}  //weight: 1, accuracy: Low
        $x_1_2 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 63 6d 64 2e 65 78 65 20 2f 63 20 63 6f 70 79 20 2f 79 20 25 54 45 4d 50 25 5c 5c [0-5] 2e 6c 6f 67 20 25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 5c [0-5] 2e 6c 6f 67 2e 6c 6f 67 22}  //weight: 1, accuracy: Low
        $x_1_3 = {52 00 75 00 6e 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 3d 00 22 00 68 00 69 00 64 00 63 00 6f 00 6e 00 3a 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 72 00 65 00 6e 00 61 00 6d 00 65 00 20 00 25 00 55 00 53 00 45 00 52 00 50 00 52 00 4f 00 46 00 49 00 4c 00 45 00 25 00 5c 00 5c 00 [0-5] 2e 00 6c 00 6f 00 67 00 2e 00 6c 00 6f 00 67 00 20 00 [0-5] 2e 00 6c 00 6f 00 67 00 2e 00 6c 00 6f 00 67 00 2e 00 76 00 62 00 73 00 22 00}  //weight: 1, accuracy: Low
        $x_1_4 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 63 6d 64 2e 65 78 65 20 2f 63 20 72 65 6e 61 6d 65 20 25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 5c [0-5] 2e 6c 6f 67 2e 6c 6f 67 20 [0-5] 2e 6c 6f 67 2e 6c 6f 67 2e 76 62 73 22}  //weight: 1, accuracy: Low
        $x_1_5 = {52 00 75 00 6e 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 3d 00 22 00 68 00 69 00 64 00 63 00 6f 00 6e 00 3a 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 2f 00 62 00 20 00 25 00 55 00 53 00 45 00 52 00 50 00 52 00 4f 00 46 00 49 00 4c 00 45 00 25 00 5c 00 5c 00 [0-5] 2e 00 6c 00 6f 00 67 00 2e 00 6c 00 6f 00 67 00 2e 00 76 00 62 00 73 00 22 00}  //weight: 1, accuracy: Low
        $x_1_6 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 2f 62 20 25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 5c [0-5] 2e 6c 6f 67 2e 6c 6f 67 2e 76 62 73 22}  //weight: 1, accuracy: Low
        $x_1_7 = {52 00 75 00 6e 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 3d 00 22 00 68 00 69 00 64 00 63 00 6f 00 6e 00 3a 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 64 00 65 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 71 00 20 00 25 00 55 00 53 00 45 00 52 00 50 00 52 00 4f 00 46 00 49 00 4c 00 45 00 25 00 5c 00 5c 00 [0-5] 2e 00 6c 00 6f 00 67 00 2e 00 6c 00 6f 00 67 00 2e 00 76 00 62 00 73 00 22 00}  //weight: 1, accuracy: Low
        $x_1_8 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 63 6d 64 2e 65 78 65 20 2f 63 20 64 65 6c 20 2f 66 20 2f 71 20 25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 5c [0-5] 2e 6c 6f 67 2e 6c 6f 67 2e 76 62 73 22}  //weight: 1, accuracy: Low
        $x_1_9 = "GUIMode=\"2\"" ascii //weight: 1
        $x_1_10 = "InstallPath=\"%TEMP%\"" ascii //weight: 1
        $x_1_11 = "SelfDelete=\"1\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Pterodo_YAA_2147895014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pterodo.YAA!MTB"
        threat_id = "2147895014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pterodo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 08 5b 89 5d fc 8b 45 2c 8b 7d 0c 89 7d 14 8b 4d 24 8a 54 08 ff 84 d2 74 cf 30 14 08 eb ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pterodo_YAC_2147903891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pterodo.YAC!MTB"
        threat_id = "2147903891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pterodo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 d0 8b 75 cc 01 f0 8b 4d e0 74 11 4e 8a 44 31 ff 84 c0 74 03 30 04 31 4e 39 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pterodo_YAD_2147907055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pterodo.YAD!MTB"
        threat_id = "2147907055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pterodo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 08 8b 55 ?? 03 55 e0 0f b6 42 ff 33 c8 8b 55 ?? 03 55 e0 88 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pterodo_YAE_2147907056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pterodo.YAE!MTB"
        threat_id = "2147907056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pterodo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 ea 01 0f b6 0c 11 31 c8 88 c2 8b 86 0c 32 00 00 8b 8e 04 32 00 00 88 14 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pterodo_YAG_2147909057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pterodo.YAG!MTB"
        threat_id = "2147909057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pterodo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 44 11 ff 84 c0 74 03 30 04 11 4a 39 d7 75 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pterodo_MKV_2147915152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pterodo.MKV!MTB"
        threat_id = "2147915152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pterodo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 0c 06 8d 48 fe 0f b6 54 06 fe 84 d2 74 de 30 54 06 ff eb d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

