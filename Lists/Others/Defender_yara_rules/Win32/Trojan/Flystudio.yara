rule Trojan_Win32_Flystudio_MR_2147772401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Flystudio.MR!MTB"
        threat_id = "2147772401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Flystudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ExuiKrnln.ini" wide //weight: 1
        $x_1_2 = "note.youdao.com/yws/public/note" ascii //weight: 1
        $x_1_3 = "\\Clear.bat" ascii //weight: 1
        $x_1_4 = "FYFireWall.exe" ascii //weight: 1
        $x_1_5 = "avcenter.exe" ascii //weight: 1
        $x_1_6 = "I@npaplayer.dll" ascii //weight: 1
        $x_1_7 = "IEXT2_IDR_WAVE1" ascii //weight: 1
        $x_1_8 = "Reply-To: %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Flystudio_RF_2147787103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Flystudio.RF!MTB"
        threat_id = "2147787103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Flystudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "F7FC1AE45C5C4758AF03EF19F18A395D" ascii //weight: 1
        $x_1_2 = "fuck.ini" ascii //weight: 1
        $x_1_3 = "http\\shell\\open\\command" ascii //weight: 1
        $x_1_4 = "https://hao.360.cn/" ascii //weight: 1
        $x_1_5 = "http://www.2345.com/" ascii //weight: 1
        $x_1_6 = "taobao.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Flystudio_RW_2147789423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Flystudio.RW!MTB"
        threat_id = "2147789423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Flystudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {83 ec 0c 50 ff 74 24 ?? 33 c0 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 8d 54 24 ?? 52 ff d3 8b 44 24 ?? 8b 54 24 ?? 8b 4c 24 ?? 83 c4 18}  //weight: 20, accuracy: Low
        $x_1_2 = "_EL_HideOwner" ascii //weight: 1
        $x_1_3 = "include \\l.chs\\afxres.rc" ascii //weight: 1
        $x_1_4 = "T$0VRPSQ" ascii //weight: 1
        $x_1_5 = "T$TQRPhx" ascii //weight: 1
        $x_1_6 = "VirtualAllocEx" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "ImageList_Destroy" ascii //weight: 1
        $x_1_9 = "ShellExecuteA" ascii //weight: 1
        $x_1_10 = "GetStartupInfoA" ascii //weight: 1
        $x_1_11 = "GetCPInfo" ascii //weight: 1
        $x_1_12 = "\\EasyAntiCheat_x86.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Flystudio_DA_2147795787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Flystudio.DA!MTB"
        threat_id = "2147795787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Flystudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "aHRsNTY1NjU1Ni51MS5sdXlvdXhpYS5uZXR8NTMwNzE=" ascii //weight: 1
        $x_1_2 = "taskkill /im cmd.exe" ascii //weight: 1
        $x_1_3 = "cmd.exe /c del svchcst.exe" ascii //weight: 1
        $x_1_4 = "Microsoft\\svchcst.exe" ascii //weight: 1
        $x_1_5 = {4d 69 63 72 6f 73 6f 66 74 5c [0-15] 2e 62 61 74}  //weight: 1, accuracy: Low
        $x_1_6 = {5c 53 74 61 72 74 75 70 5c [0-15] 2e 6c 6e 6b}  //weight: 1, accuracy: Low
        $x_1_7 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Flystudio_GPN_2147894387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Flystudio.GPN!MTB"
        threat_id = "2147894387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Flystudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {c0 e0 04 c1 eb 03 32 d8 c1 e9 05 8a c2 c0 e0 02 32 c8 8b 45 f8 02 d9 83 e0 03 8b 4d 08 33 c6 8a 0c 81 32 4d fc 8a 45 f4 32 c2 02 c8 32 d9 8b 4d f8 00 1c 39}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Flystudio_NF_2147899074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Flystudio.NF!MTB"
        threat_id = "2147899074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Flystudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 db 39 1d ?? ?? ?? ?? 56 57 75 05 e8 44 fd ff ff be b0 f1 4d}  //weight: 5, accuracy: Low
        $x_5_2 = {a1 64 08 4e 00 89 35 ?? ?? ?? ?? 8b fe 38 18 74 02 8b f8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Flystudio_NF_2147899074_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Flystudio.NF!MTB"
        threat_id = "2147899074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Flystudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {eb de 8d 45 ?? 50 ff 15 9c 21 47 00 66 83 7d ea 00 0f 84 d1}  //weight: 5, accuracy: Low
        $x_5_2 = {83 f9 ff 74 38 8a 03 a8 01 74 32 a8 ?? 75 0b 51 ff 15 50 23 47}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Flystudio_NF_2147899074_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Flystudio.NF!MTB"
        threat_id = "2147899074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Flystudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {3b f0 73 1e 80 66 04 00 83 0e ?? 83 66 08 00 c6 46 05 ?? a1 60 bc 61 00 83 c6 ?? 05 80 04 00 00 eb de}  //weight: 5, accuracy: Low
        $x_1_2 = {eb de 8d 45 ?? 50 ff 15 94 51 49 00 66 83 7d ?? 00 0f 84 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Flystudio_A_2147920520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Flystudio.A!MTB"
        threat_id = "2147920520"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Flystudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4c 24 08 53 55 8b ac 24 2c 02 00 00 55 6a 00 6a 00 51 68 74 ad ba 00 6a 00 ?? ?? ?? ?? ?? ?? 8b f0 83 fe 20 [0-17] 8b cf 52 68 6c ad ba 00 68 00 00 00 80 ?? ?? ?? ?? ?? 85 c0}  //weight: 2, accuracy: Low
        $x_10_2 = {83 ec 0c 50 ff 74 24 ?? 33 c0 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 8d 54 24 ?? 52 ff d3 8b 44 24 ?? 8b 54 24 ?? 8b 4c 24 ?? 83 c4 18}  //weight: 10, accuracy: Low
        $x_2_3 = {8a 0c 02 03 d0 03 d8 2b e8 3b e8 88 0b 77 f1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Flystudio_B_2147936262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Flystudio.B!MTB"
        threat_id = "2147936262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Flystudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 07 8b 4f 04 66 81 fe a0 72 3b e4 8d bf 04 00 00 00 33 d2 e9 4d 0f fc ff ff d0}  //weight: 1, accuracy: High
        $x_1_2 = {66 0f be da 0f cb 5b 5f 8b e5 0f bf ef 87 ed 5d e9 4c 4c ed fe}  //weight: 1, accuracy: High
        $x_2_3 = {d0 c2 66 d3 c0 66 c1 f0 d9 80 ea a1 d0 ca 80 ea 77 66 2d 58 5f 66 0f a4 e0 71 32 da 66 c1 e8 89 66 0f a4 e8 7a 66 0f be c1 66 0f b6 04 14}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Flystudio_AB_2147936814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Flystudio.AB!MTB"
        threat_id = "2147936814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Flystudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 46 2c 85 c0 74 0b 50 ff 15 88 25 4a 00 83 66 2c 00 83 7e 14 00 74 08 83 66 14 00 33 c0}  //weight: 2, accuracy: High
        $x_10_2 = {83 ec 0c 50 ff 74 24 ?? 33 c0 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 8d 54 24 ?? 52 ff d3 8b 44 24 ?? 8b 54 24 ?? 8b 4c 24 ?? 83 c4 18}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Flystudio_DB_2147939992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Flystudio.DB!MTB"
        threat_id = "2147939992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Flystudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "140"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {39 00 34 00 2d 00 31 00 33 00 34 00 33 00 31 00 33 00 32 00 36 00 33 00 36 00 2e 00 63 00 6f 00 73 00 2e 00 61 00 70 00 2d 00 6e 00 61 00 6e 00 6a 00 69 00 6e 00 67 00 2e 00 6d 00 79 00 71 00 63 00 6c 00 6f 00 75 00 64 00 2e 00 63 00 6f 00 6d 00 2f 00 [0-50] 2e 00 74 00 78 00 74 00}  //weight: 10, accuracy: Low
        $x_10_2 = {39 34 2d 31 33 34 33 31 33 32 36 33 36 2e 63 6f 73 2e 61 70 2d 6e 61 6e 6a 69 6e 67 2e 6d 79 71 63 6c 6f 75 64 2e 63 6f 6d 2f [0-50] 2e 74 78 74}  //weight: 10, accuracy: Low
        $x_100_3 = "csgonec.lanzn.com" ascii //weight: 100
        $x_10_4 = "SetCredentials" ascii //weight: 10
        $x_10_5 = "set-cookie:" ascii //weight: 10
        $x_10_6 = "SetRequestHeader" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 4 of ($x_10_*))) or
            (all of ($x*))
        )
}

