rule TrojanDownloader_Win32_Dogrobot_J_2147610778_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dogrobot.gen!J"
        threat_id = "2147610778"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 30 0f be 34 1f 83 fe 20 7c 22 83 fe 7e 7f 1d e8 ?? ?? 00 00 8d 0c 40 c1 e1 05 8d 44 31 e0 b9 5f 00 00 00 99 f7 f9 80 c2 20 88 14 1f 47 3b fd 7c d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dogrobot_A_2147611326_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dogrobot.A"
        threat_id = "2147611326"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {81 3d b0 d4 40 00 ae 08 00 00 0f 84 87 00 00 00 80 a5 f8 fe ff ff 00 6a 18 59 33 c0}  //weight: 4, accuracy: High
        $x_4_2 = {8a 0c 32 8a c2 2c 3b 8b fe d0 e0 02 c8 33 c0 88 0c 32 83 c9 ff 42 f2 ae f7 d1 49 3b d1 72 e1}  //weight: 4, accuracy: High
        $x_4_3 = {6a 01 68 99 03 00 00 07 01 01 01 01 01 01 04 50 51 52 53 56 57 68 ?? ?? ?? ?? 6a 01 e8 ?? ?? 00 00 83 c4 ?? 68 f4 01 00 00 ff 15 ?? ?? ?? ?? [0-16] 6a 05}  //weight: 4, accuracy: Low
        $x_1_4 = "\\down.sys" ascii //weight: 1
        $x_1_5 = "%02X-%02X-%02X-%02X-%02X-%02X" ascii //weight: 1
        $x_1_6 = "\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_7 = "IEProtAccess" ascii //weight: 1
        $x_1_8 = {3f 78 3d 00 26 79 3d 00 47 4f 4f 47 4c 45}  //weight: 1, accuracy: High
        $x_1_9 = {4d 79 45 6e 74 72 79 50 6f 69 6e 74 [0-5] 6c 70 6b 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_10 = "%s%d_res.tmp" ascii //weight: 1
        $x_1_11 = "kaka" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Dogrobot_B_2147617630_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dogrobot.B"
        threat_id = "2147617630"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 81 ee cf 02 00 00 81 fe 00 00 00 10 0f 87 ?? ?? 00 00 53 57 6a 00 6a 00 68 cf 02 00 00 55 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "rubbish\\dnloaerc\\Release\\dnloaderc.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dogrobot_D_2147624419_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dogrobot.D"
        threat_id = "2147624419"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 c6 45 f6 74 c6 45 f7 63 c6 45 f8 5c c6 45 f9 68 c6 45 fa 6f c6 45 fb 73 c6 45 fc 74 c6 45 fd 73}  //weight: 1, accuracy: High
        $x_1_2 = {73 66 a5 c6 45 ?? 63 c6 45 ?? 76 c6 45 ?? 68 c6 45 ?? 6f c6 45 ?? 73 c6 45 ?? 74 c6 45 ?? 2e c6 45 ?? 65 c6 45 ?? 78 c6 45 ?? 65}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4d 0c 31 06 46 e2 fb 57}  //weight: 1, accuracy: High
        $x_1_4 = {58 45 54 54 45 54 54 2e 2e 2e 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_5 = {26 64 74 69 6d 65 3d [0-5] 26 6f 73 3d [0-5] 26 76 65 72 3d [0-5] 3f 6d 61 63 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Dogrobot_C_2147624450_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dogrobot.C"
        threat_id = "2147624450"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d 0c 31 06 46 e2 fb 8b fa 83 c9 ff 33 c0 8b 5d 10}  //weight: 1, accuracy: High
        $x_1_2 = {8a 0e 8a 10 2a d1 88 10 8a ca 8a 16 32 d1 46 88 10 40 4f 75 e4}  //weight: 1, accuracy: High
        $x_1_3 = "%s%d_xeex.exe" ascii //weight: 1
        $x_1_4 = {6a 00 8d 54 24 18 68 04 01 00 00 52 57 56 ff 15 90 01 04 85 c0 75 0c}  //weight: 1, accuracy: High
        $x_1_5 = "count.asp?mac=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Dogrobot_E_2147624793_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dogrobot.E"
        threat_id = "2147624793"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 08 b8 03 00 00 00 8b 4d 0c 31 06 46 e2 fb 8b fa 83 c9 ff 33 c0 8b 5d 10}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 8d 54 24 18 68 04 01 00 00 52 57 56 ff 15 ?? ?? ?? ?? 85 c0 75 0c}  //weight: 1, accuracy: Low
        $x_1_3 = "count.asp?mac=" ascii //weight: 1
        $x_1_4 = {8b 44 24 10 80 3e 00 75 02 8b f5 8a 0e 8a 10 2a d1 88 10 8a ca 8a 16 32 d1 46 88 10 40 4f 75 e4}  //weight: 1, accuracy: High
        $x_1_5 = "%s\\%d_xeex.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

