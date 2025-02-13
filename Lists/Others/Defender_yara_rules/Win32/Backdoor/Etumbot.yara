rule Backdoor_Win32_Etumbot_2147707419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Etumbot.gen!dha"
        threat_id = "2147707419"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Etumbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 52 c6 85 ?? ?? ff ff 55 c6 85 ?? ?? ff ff 4e c6 85 ?? ?? ff ff 20 c6 85 ?? ?? ff ff 45 c6 85 ?? ?? ff ff 52 c6 85 ?? ?? ff ff 52 08 00 3b c3 75 ?? c6 85}  //weight: 1, accuracy: Low
        $x_1_2 = {f3 ab 66 ab c6 45 ?? 62 c6 45 ?? 36 c6 45 ?? 34 c6 45 ?? 5f c6 45 ?? 6e c6 45 ?? 74 c6 45 ?? 6f c6 45 ?? 70 c6 45 ?? 20 c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 72}  //weight: 1, accuracy: Low
        $x_1_3 = {66 ab aa c6 85 ?? ?? ff ff 2f c6 85 ?? ?? ff ff 53 c6 85 ?? ?? ff ff 55 c6 85 ?? ?? ff ff 53 c6 85 ?? ?? ff ff 25 c6 85 ?? ?? ff ff 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Etumbot_B_2147707420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Etumbot.B!dha"
        threat_id = "2147707420"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Etumbot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 41 c6 85 ?? ?? ff ff 50 c6 85 ?? ?? ff ff 50 c6 85 ?? ?? ff ff 44 c6 85 ?? ?? ff ff 41 c6 85 ?? ?? ff ff 54 c6 85 ?? ?? ff ff 41 c6 85 ?? ?? ff ff 00}  //weight: 1, accuracy: Low
        $x_1_2 = {56 57 c6 85 ?? ?? ff ff 61 c6 85 ?? ?? ff ff 66 c6 85 ?? ?? ff ff 6a c6 85 ?? ?? ff ff 6c c6 85 ?? ?? ff ff 66 c6 85 ?? ?? ff ff 6a c6 85 ?? ?? ff ff 73 c6 85 ?? ?? ff ff 73 c6 85 ?? ?? ff ff 6b}  //weight: 1, accuracy: Low
        $x_1_3 = {56 57 c6 45 ?? 61 c6 45 ?? 66 c6 45 ?? 6a c6 45 ?? 6c c6 45 ?? 66 c6 45 ?? 6a c6 45 ?? 73 c6 45 ?? 73 c6 45 ?? 6b}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 c0 8b 45 08 50 ff 15 10 00 c6 45 ?? 65 c6 45 ?? 78 c6 45 ?? 65 c6 45 ?? 00}  //weight: 1, accuracy: Low
        $x_1_5 = {c6 45 f0 42 c6 45 f1 49 c6 45 f2 4e c6 45 f3 41 c6 45 f4 52 c6 45 f5 59 80 65 f6 00 e9 04 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {ff ff 6b c6 85 ?? ?? ff ff 62 c6 85 ?? ?? ff ff 37 c6 85 ?? ?? ff ff 31 c6 85 ?? ?? ff ff 32 c6 85 ?? ?? ff ff 37 c6 85 ?? ?? ff ff 31 c6 85 ?? ?? ff ff 2e c6 85 ?? ?? ff ff 6c c6 85 ?? ?? ff ff 6f c6 85 ?? ?? ff ff 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Etumbot_C_2147708493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Etumbot.C!dha"
        threat_id = "2147708493"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Etumbot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 85 18 e4 ff ff 04 00 00 00 c7 85 64 ff ff ff 4d 6f 7a 69 c7 85 68 ff ff ff 6c 6c 61 2f c7 85 6c ff ff ff 35 2e 30 20 c7 85 70 ff ff ff 28 57 69 6e c7 85 74 ff ff ff 64 6f 77 73 c7 85 78 ff ff ff 20 4e 54 20 c7 85 7c ff ff ff 36 2e 31 3b c7 45 80 20 72 76 3a c7 45 84 34 33 2e 30 c7 45 88 29 20 47 65 c7 45 8c 63 6b 6f 2f c7 45 90 32 30 31 30 c7 45 94 30 31 30 31 c7 45 98 20 46 69 72 c7 45 9c 65 66 6f 78 c7 45 a0 2f 34 33 2e}  //weight: 1, accuracy: High
        $x_1_2 = {ff ff ff 53 6f 66 74 c7 85 ?? ff ff ff 77 61 72 65 c7 85 ?? ff ff ff 5c 4d 69 63 c7 85 ?? ff ff ff 72 6f 73 6f c7 85 ?? ff ff ff 66 74 5c 57 c7 85 ?? ff ff ff 69 6e 64 6f}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 45 d4 6f 72 5b 25 c7 45 d8 64 5d 2e 0d}  //weight: 1, accuracy: High
        $x_1_4 = {c7 45 88 2f 53 44 55 c7 45 8c 25 64 3d 25 c7 45 90 64 2e 63 67 c7 45 94 69 3f 25 73}  //weight: 1, accuracy: High
        $x_1_5 = {ff ff ff 2f 44 45 53 c7 85 ?? ff ff ff 25 64 3d 25 c7 85 ?? ff ff ff 64 2e 63 67 c7 85 ?? ff ff ff 69 3f 25 73}  //weight: 1, accuracy: Low
        $x_1_6 = {c7 45 90 4d 6f 7a 69 c7 45 94 6c 6c 61 2f c7 45 98 34 2e 30 20 c7 45 9c 28 63 6f 6d c7 45 a0 70 61 74 69 c7 45 a4 62 6c 65 3b c7 45 a8 20 4d 53 49 c7 45 ac 45 20 37 2e c7 45 b0 30 3b 20 57 c7 45 b4 69 6e 33 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Etumbot_D_2147708565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Etumbot.D!dha"
        threat_id = "2147708565"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Etumbot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 f4 61 70 70 64 c7 45 f8 61 74 61 00 c7 85 ?? f9 ff ff 5c 76 65 63 c7 85 ?? f9 ff ff 6f 6d 65 2e c7 85 ?? f9 ff ff 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 ff ff 49 45 58 50 c7 85 ?? f8 ff ff 4c 4f 52 45 c7 85 ?? f8 ff ff 2e 45 58 45}  //weight: 1, accuracy: Low
        $x_1_3 = {f6 ff ff 63 68 72 6f c7 85 ?? f7 ff ff 6d 65 2e 65 66 c7 ?? 04 f7 ff ff 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {fc ff ff 77 6b 73 63 c7 85 ?? fc ff ff 6c 69 76 2e c7 85 ?? fc ff ff 64 6c 6c 00 c7 85 ?? fc ff ff 5c 4c 6f 63 c7 85 ?? fc ff ff 61 74 69 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Etumbot_E_2147709011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Etumbot.E!dha"
        threat_id = "2147709011"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Etumbot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 43 45 4c 25 64 3d 25 64 2e 63 67 69 3f 25 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {2f 53 44 55 25 64 3d 25 64 2e 63 67 69 3f 25 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {c6 85 47 ff ff ff 25 c6 85 48 ff ff ff 64 c6 85 49 ff ff ff 2e c6 85 4a ff ff ff 63 c6 85 4b ff ff ff 67 c6 85 4c ff ff ff 69 c6 85 4d ff ff ff 3f c6 85 4e ff ff ff 25 c6 85 4f ff ff ff 73}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 e8 20 c6 45 e9 65 c6 45 ea 72 c6 45 eb 72 c6 45 ec 6f c6 45 ed 72 c6 45 ee 5b}  //weight: 1, accuracy: High
        $x_1_5 = {c6 45 c4 62 c6 45 c5 36 c6 45 c6 34 c6 45 c7 5f c6 45 c8 6e c6 45 c9 74 c6 45 ca 6f c6 45 cb 70}  //weight: 1, accuracy: High
        $x_1_6 = {c6 45 e6 77 c6 45 e7 72 c6 45 e8 6f c6 45 e9 74 c6 45 ea 65 c6 45 eb 28 c6 45 ec 25 c6 45 ed 64 c6 45 ee 29 c6 45 ef 2e}  //weight: 1, accuracy: High
        $x_1_7 = {66 c7 85 48 f1 ff ff 6f 00 66 c7 85 4a f1 ff ff 6e 00 66 c7 85 4c f1 ff ff 6c 00 66 c7 85 4e f1 ff ff 69 00 66 c7 85 50 f1 ff ff 6e 00 66 c7 85 52 f1 ff ff 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {c6 85 90 c7 ff ff 2b c6 85 91 c7 ff ff 4f c6 85 92 c7 ff ff 4b c6 85 93 c7 ff ff 20 c6 85 94 c7 ff ff 43 c6 85 95 c7 ff ff 45 c6 85 96 c7 ff ff 4c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Etumbot_2147709096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Etumbot!dha"
        threat_id = "2147709096"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Etumbot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetProcessId() to failed!" ascii //weight: 1
        $x_1_2 = "CreateProcessAsUser() = %d" ascii //weight: 1
        $x_1_3 = "Allocate SID or ACL to failed!" ascii //weight: 1
        $x_1_4 = "Allocate pSd memory to failed!" ascii //weight: 1
        $x_5_5 = {c6 44 24 19 50 c6 44 24 1a 41 c6 44 24 1b 73 c6 44 24 1c 55 c6 44 24 1d 73 c6 44 24 20 3a 88 4c 24 21 88 5c 24 25 c6 44 24 26 74 c6 44 24 28 50 88 54 24 2a c6 44 24 2b 63 c6 44 24 2d 73 c6 44 24 2e 73 c6 44 24 2f 28 c6 44 24 30 29 88 4c 24 31}  //weight: 5, accuracy: High
        $x_5_6 = {c6 44 24 32 74 88 54 24 33 88 4c 24 34 c6 44 24 35 66 88 5c 24 36 c6 44 24 37 69 c6 44 24 38 6c c6 44 24 3a 64 c6 44 24 3b 21}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Etumbot_F_2147710101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Etumbot.F!dha"
        threat_id = "2147710101"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Etumbot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 f4 41 c6 45 f5 75 c6 45 f6 64 c6 45 f7 69 c6 45 f8 6f c6 45 f9 4d c6 45 fa 67 c6 45 fb 72 89 4d e4}  //weight: 1, accuracy: High
        $x_1_2 = {c6 85 00 fe ff ff 34 c6 85 01 fe ff ff 34 c6 85 02 fe ff ff 33 ?? ?? ?? fe ff ff 00}  //weight: 1, accuracy: Low
        $x_1_3 = {ee ff ff 2f c6 85 ?? ee ff ff 41 c6 85 ?? ee ff ff 4c c6 85 ?? ee ff ff 49 c6 85 ?? ee ff ff 56 c6 85 ?? ee ff ff 45 c6 85 ?? ee ff ff 20 c6 85 ?? ee ff ff 25 c6 85 ?? ee ff ff 64 c6 85 ?? ee ff ff 20 c6 85 ?? ee ff ff 25 c6 85 ?? ee ff ff 64 c6 85 ?? ee ff ff 0d}  //weight: 1, accuracy: Low
        $x_1_4 = {ef ff ff 57 c6 85 ?? ef ff ff 49 c6 85 ?? ef ff ff 4e c6 85 ?? ef ff ff 44 c6 85 ?? ef ff ff 4f c6 85 ?? ef ff ff 57 c6 85 ?? ef ff ff 53 c6 85 ?? ef ff ff 20 c6 85 ?? ef ff ff 43 c6 85 ?? ef ff ff 4f c6 85 ?? ef ff ff 4d c6 85 ?? ef ff ff 4d c6 85 ?? ef ff ff 41 c6 85 ?? ef ff ff 4e c6 85 ?? ef ff ff 44 c6 85 ?? ef ff ff 20 c6 85 ?? ef ff ff 53 c6 85 ?? ef ff ff 48 c6 85 ?? ef ff ff 45 c6 85 ?? ef ff ff 4c c6 85 ?? ef ff ff 4c}  //weight: 1, accuracy: Low
        $x_1_5 = {df ff ff 2f c6 85 ?? df ff ff 53 c6 85 ?? df ff ff 4c c6 85 ?? df ff ff 45 c6 85 ?? df ff ff 45 c6 85 ?? df ff ff 50 c6 85 ?? df ff ff 20 c6 85 ?? df ff ff 25 c6 85 ?? df ff ff 73 c6 85 ?? df ff ff 0d c6 85 ?? df ff ff 0a}  //weight: 1, accuracy: Low
        $x_1_6 = {c6 44 24 34 48 c6 44 24 35 49 c6 44 24 36 44 c6 44 24 37 45 c6 44 24 38 30 c6 44 24 3c 00 88 5c 24 0a c6 44 24 0d 73 88 5c 24 0f c6 44 24 12 73 88 5c 24 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Etumbot_G_2147710390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Etumbot.G!dha"
        threat_id = "2147710390"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Etumbot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 e9 77 c6 45 ea 72 c6 45 eb 6f c6 45 ec 74 c6 45 ed 65 c6 45 ee 28 c6 45 ef 25 c6 45 f0 64 c6 45 f1 29 c6 45 f2 2e}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 b5 45 c6 45 b6 52 c6 45 b7 52 c6 45 b8 20}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 e8 45 c6 45 e9 52 c6 45 ea 52 c6 45 eb 20 c6 45 ec 27 c6 45 ed 25 c6 45 ee 73 c6 45 ef 27}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 b6 2f c6 45 b7 25 c6 45 b8 64 c6 45 b9 2e c6 45 ba 70 c6 45 bb 68 c6 45 bc 70 c6 45 bd 3f c6 45 be 25 c6 45 bf 73}  //weight: 1, accuracy: High
        $x_1_5 = {c6 45 e4 50 c6 45 e5 72 c6 45 e6 6f c6 45 e7 78 c6 45 e8 79 c6 45 e9 53 c6 45 ea 65 c6 45 eb 72 c6 45 ec 76 c6 45 ed 65 c6 45 ee 72}  //weight: 1, accuracy: High
        $x_1_6 = {c6 85 64 cd ff ff 52 c6 85 65 cd ff ff 45 c6 85 66 cd ff ff 51 c6 85 67 cd ff ff 20 c6 85 68 cd ff ff 25 c6 85 69 cd ff ff 64 c6 85 6a cd ff ff 0d}  //weight: 1, accuracy: High
        $x_1_7 = {c6 45 c4 62 c6 45 c5 36 c6 45 c6 34 c6 45 c7 5f c6 45 c8 6e c6 45 c9 74 c6 45 ca 6f c6 45 cb 70 c6 45 cc 20 c6 45 cd 65 c6 45 ce 72 c6 45 cf 72 c6 45 d0 6f c6 45 d1 72 c6 45 d2 5b c6 45 d3 25}  //weight: 1, accuracy: High
        $x_1_8 = {c6 45 d0 20 c6 45 d1 65 c6 45 d2 78 c6 45 d3 65 c6 45 d4 63 c6 45 d5 75 c6 45 d6 74 c6 45 d7 65 c6 45 d8 64 c6 45 d9 2e}  //weight: 1, accuracy: High
        $x_1_9 = {c6 85 a9 c7 ff ff 58 c6 85 aa c7 ff ff 44 c6 85 ab c7 ff ff 55 c6 85 ac c7 ff ff 25 c6 85 ad c7 ff ff 64 c6 85 ae c7 ff ff 3d c6 85 af c7 ff ff 25 c6 85 b0 c7 ff ff 64 c6 85 b1 c7 ff ff 2e c6 85 b2 c7 ff ff 63 c6 85 b3 c7 ff ff 67 c6 85 b4 c7 ff ff 69 c6 85 b5 c7 ff ff 3f c6 85 b6 c7 ff ff 25 c6 85 b7 c7 ff ff 73}  //weight: 1, accuracy: High
        $x_1_10 = {66 c7 85 4c f1 ff ff 73 00 66 c7 85 4e f1 ff ff 75 00 66 c7 85 50 f1 ff ff 63 00 66 c7 85 52 f1 ff ff 63 00 66 c7 85 54 f1 ff ff 65 00 66 c7 85 56 f1 ff ff 73 00 66 c7 85 58 f1 ff ff 73 00}  //weight: 1, accuracy: High
        $x_1_11 = {c6 85 a9 f6 ff ff 75 c6 85 aa f6 ff ff 73 c6 85 ab f6 ff ff 65 c6 85 ac f6 ff ff 72 c6 85 ad f6 ff ff 2f c6 85 ae f6 ff ff 72 c6 85 af f6 ff ff 65 c6 85 b0 f6 ff ff 67 c6 85 b1 f6 ff ff 69 c6 85 b2 f6 ff ff 73 c6 85 b3 f6 ff ff 74 c6 85 b4 f6 ff ff 65 c6 85 b5 f6 ff ff 72 c6 85 b6 f6 ff ff 25 c6 85 b7 f6 ff ff 64}  //weight: 1, accuracy: High
        $x_1_12 = {c6 85 cf f6 ff ff 65 c6 85 d0 f6 ff ff 70 c6 85 d1 f6 ff ff 61 c6 85 d2 f6 ff ff 67 c6 85 d3 f6 ff ff 65 c6 85 d4 f6 ff ff 26 c6 85 d5 f6 ff ff 75 c6 85 d6 f6 ff ff 72 c6 85 d7 f6 ff ff 6c c6 85 d8 f6 ff ff 3d c6 85 d9 f6 ff ff 68 c6 85 da f6 ff ff 74 c6 85 db f6 ff ff 74 c6 85 dc f6 ff ff 70 c6 85 dd f6 ff ff 73 c6 85 de f6 ff ff 25 c6 85 df f6 ff ff 73}  //weight: 1, accuracy: High
        $x_1_13 = {68 51 0f ef ff f5 26 85 11 fe ff ff 65 68 51 2f ef ff f6 36 85 13 fe ff ff 65 68 51 4f ef ff f6 96 85 15 fe ff ff 76 68 51 6f ef ff f6 56 85 17 fe ff ff 20 68 51 8f ef ff f4 36 85 19 fe ff ff 6f 68 51 af ef ff f6 d6 85 1b fe ff ff 6d 68 51 cf ef ff f6 16 85 1d fe ff ff 6e 68 51 ef ef ff f6}  //weight: 1, accuracy: High
        $x_1_14 = {c6 85 30 ff ff ff 50 c6 85 31 ff ff ff 72 c6 85 32 ff ff ff 6f c6 85 33 ff ff ff 78 c6 85 34 ff ff ff 79 c6 85 35 ff ff ff 53 c6 85 36 ff ff ff 65 c6 85 37 ff ff ff 72 c6 85 38 ff ff ff 76 c6 85 39 ff ff ff 65 c6 85 3a ff ff ff 72}  //weight: 1, accuracy: High
        $x_1_15 = {c6 45 e4 53 c6 45 e5 68 c6 45 e6 65 c6 45 e7 6c c6 45 e8 6c c6 45 e9 20 c6 45 ea 45 c6 45 eb 78 c6 45 ec 69 c6 45 ed 74 c6 45 ee 65 c6 45 ef 64 c6 45 f0 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

