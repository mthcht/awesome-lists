rule Trojan_Win32_ValleyRat_AVA_2147929127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.AVA!MTB"
        threat_id = "2147929127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 56 57 6a 00 6a 00 68 04 01 00 00 8d 44 24 24 8b f9 50 68 b0 53 40 00 89 7c 24 24 6a 00 89 7c 24 28 ff 15}  //weight: 2, accuracy: High
        $x_1_2 = {2b 45 e0 6a 40 68 00 30 00 00 50 6a 00 ff 15 ?? ?? ?? ?? 8b f0 85 f6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_AVA_2147929127_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.AVA!MTB"
        threat_id = "2147929127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {50 68 c8 51 41 00 8b 4d fc 51 e8 ?? ?? ?? ?? 83 c4 0c 6a 00 6a 00 68 ec 51 41 00 68 20 52 41 00 68 30 52 41 00 6a 00 ff 15}  //weight: 3, accuracy: Low
        $x_1_2 = "Successfully created scheduled task" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_BSA_2147929167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.BSA!MTB"
        threat_id = "2147929167"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 54 24 0c 8b 4c 24 04 85 d2 74 69 33 c0 8a 44 24 08 84 c0 75 16 81 fa 80 00 00 00 72 0e 83 3d 08 13 58 00 00 74 05 e9 0b 9d}  //weight: 10, accuracy: High
        $x_5_2 = {66 0f ef c0 51 53 8b c1 83 e0 0f 85 c0 75 7f 8b c2 83 e2 7f c1 e8 07 74 37 8d a4 24}  //weight: 5, accuracy: High
        $x_5_3 = {8b d8 f7 db 83 c3 10 2b d3 33 c0 52 8b d3 83 e2 03 74 06}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_BSA_2147929167_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.BSA!MTB"
        threat_id = "2147929167"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 56 eb 13 ?? ?? ?? ?? ?? 85 c0 74 19 ff 75 08 ff d0 59 85 c0 74 0f ff 75 08 e8 97 e9 0f 00 8b f0 59 85 f6 74 de 8b c6}  //weight: 10, accuracy: Low
        $x_2_2 = {85 c0 74 19 ff 75 08 ff d0 59 85 c0 74 0f ff 75 08}  //weight: 2, accuracy: High
        $x_2_3 = {ff 73 64 c7 45 d4 ?? ?? ?? ?? ff d6 6a 04 8d 45 d4 50 68}  //weight: 2, accuracy: Low
        $x_8_4 = {8b 44 24 10 89 6c 24 10 8d 6c 24 10 2b e0 53 56 57 a1 ?? ?? ?? ?? 31 45 fc 33 c5 50 89 65 e8 ff 75 f8 8b 45 fc c7 45 fc ?? ?? ?? ?? 89 45 f8 8d 45 f0 64 a3 00}  //weight: 8, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_BJK_2147934531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.BJK!MTB"
        threat_id = "2147934531"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff d5 99 b9 3e 00 00 00 f7 f9 46 3b f3 8a 54 14 10 88 54 3e ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_MHS_2147934902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.MHS!MTB"
        threat_id = "2147934902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 04 49 8d 04 45 07 00 00 00 35 84 18 f1 ba 03 05 c8 f6 42 00 68 08 0a 43 00 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_AVE_2147943647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.AVE!MTB"
        threat_id = "2147943647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 83 ec 1c 8b 45 08 8b 58 04 8b 30 c7 44 24 0c ?? ?? ?? ?? c7 44 24 08 ?? ?? ?? ?? 8b 03 c7 04 24 ?? ?? ?? ?? 89 44 24 04 ff 15 ?? ?? ?? ?? 8b 0b 89 c7 83 ec 10 f3 a4 ff d0 8d 65 f4 31 c0 5b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_PCO_2147945120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.PCO!MTB"
        threat_id = "2147945120"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 54 0d f4 0f b6 1c 38 2b da 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 41 88 1c 38 40 83 e1 07 3b c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_AVY_2147945345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.AVY!MTB"
        threat_id = "2147945345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 a8 49 c6 45 a9 6e c6 45 aa 74 c6 45 ab 65 c6 45 ac 72 c6 45 ad 6e c6 45 ae 65 c6 45 af 74 c6 45 b0 4f c6 45 b1 70 c6 45 b2 65 c6 45 b3 6e c6 45 b4 41 c6 45 b5 00 c6 45 94 49 c6 45 95 6e c6 45 96 74 c6 45 97 65 c6 45 98 72 c6 45 99 6e c6 45 9a 65 c6 45 9b 74 c6 45 9c 43 c6 45 9d 6f c6 45 9e 6e c6 45 9f 6e c6 45 a0 65 c6 45 a1 63 c6 45 a2 74 c6 45 a3 41 c6 45 a4 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_GVA_2147955992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.GVA!MTB"
        threat_id = "2147955992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {34 6e d0 06 84 2a 48 b6 69 d4 d1 52 ad}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_YAH_2147956007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.YAH!MTB"
        threat_id = "2147956007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d fc 03 4d f4 0f b6 11 83 f2 21 8b 45 fc 03 45 f4 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_NVA_2147956332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.NVA!MTB"
        threat_id = "2147956332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "TCGamerUpdateMain" ascii //weight: 2
        $x_1_2 = "\\jincheng.bat" ascii //weight: 1
        $x_1_3 = "\\backup.dll" ascii //weight: 1
        $x_1_4 = "\\jincheng.pid" ascii //weight: 1
        $x_1_5 = "BackupDLLPath" ascii //weight: 1
        $x_1_6 = "BackupProcessPath" ascii //weight: 1
        $x_1_7 = "goto CheckProcess" ascii //weight: 1
        $x_1_8 = "Update.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_CG_2147957827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.CG!MTB"
        threat_id = "2147957827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {81 f2 88 00 00 00 83 f2 66 8b 45 ?? 88 90 ?? ?? ?? ?? eb}  //weight: 5, accuracy: Low
        $x_5_2 = {0f b6 82 00 ?? ?? ?? 83 f0 1a 8b 4d ?? 88 81 ?? ?? ?? ?? eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_AMTB_2147959263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat!AMTB"
        threat_id = "2147959263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {8b 56 08 8b 45 14 8d 3c 11 8b 55 08 0f b6 04 02 99 bb c8 01 00 00 f7 fb ff 45 08 b8 cd cc cc cc 80 c2 36 30 17 f7 e1 c1 ea 03 8d 04 92 03 c0 8b d1 2b d0}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_AMTB_2147959263_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat!AMTB"
        threat_id = "2147959263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://192.238.184.214/86.bin" ascii //weight: 2
        $x_2_2 = "\\adadad\\Release\\adadad.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_AMTB_2147959263_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat!AMTB"
        threat_id = "2147959263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\Document\\_\\_\\_\\_\\_" ascii //weight: 1
        $x_1_2 = "_\\_\\_\\_\\document.bat" ascii //weight: 1
        $x_1_3 = "C:\\Users\\Administrator\\Desktop\\msimg32\\x64\\Release\\msimg32.pdb" ascii //weight: 1
        $x_1_4 = "D:\\Malware Project\\msimg32\\x64\\Release\\msimg32.pdb" ascii //weight: 1
        $x_1_5 = "msimg32.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_ValleyRat_A_2147960478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.A!AMTB"
        threat_id = "2147960478"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "schtasks /create /tn \"MicroStartApp\" /tr \"%s\" /sc onlogon /rl highest /f" ascii //weight: 3
        $x_3_2 = "C:\\Users\\AdministratorVersion\\glibcVersion\\%s.exe" ascii //weight: 3
        $x_2_3 = "Add-MpPreference -ExclusionPath %s" ascii //weight: 2
        $x_1_4 = "powershell.exe" ascii //weight: 1
        $x_1_5 = "%S#[k" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_BMD_2147960763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.BMD!MTB"
        threat_id = "2147960763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 10 3b f9 7e ?? 8b 46 08 80 34 08 ?? 41 3b cf 7c}  //weight: 2, accuracy: Low
        $x_2_2 = "%s\\shell\\open\\command" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_AP_2147961170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.AP!MTB"
        threat_id = "2147961170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 f8 83 e0 0f 30 ca 80 c1 07 32 90 12 6c 42 00 89 f8 47 83 e0 1f 32 90 f2 6b 42 00 8b 46 08 88 14 18 43 81 ff ca 09 00 00 75 cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_BCMD_2147963824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.BCMD!MTB"
        threat_id = "2147963824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 02 99 be ?? ?? ?? ?? f7 fe 83 c2 ?? 8b 45 ?? 0f be 0c 01 33 ca 8b 55 ?? 8b 42 ?? 8b 55 ?? 88 0c 10 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_CQ_2147964038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.CQ!MTB"
        threat_id = "2147964038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {34 56 8b 8d 88 fe ff ff 83 c4 04 88 04 11 42 89 95 94 fe ff ff eb 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_ARP_2147964707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.ARP!AMTB"
        threat_id = "2147964707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://45.203.220.135:8080/output_86.bin" ascii //weight: 1
        $x_1_2 = "[+] Downloaded and encrypted %d bytes" ascii //weight: 1
        $x_1_3 = "[*] Starting encrypted download loader" ascii //weight: 1
        $x_1_4 = "runas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_AYV_2147966168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.AYV!MTB"
        threat_id = "2147966168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 d4 b9 12 00 00 00 c7 45 e4 4b 00 00 00 be e0 b4 01 10 c7 45 e8 4f 00 00 00 8b f8 f3 a5 83 c4 04 66 a5 a4 c6 40 4b 00 8d 55 d4 c7 45 fc 00 00 00 00 8d 4d c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_AYV_2147966168_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.AYV!MTB"
        threat_id = "2147966168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d0 ff 35 b0 80 43 00 e8 ?? ?? ?? ?? ff 35 b0 80 43 00 8b f0 6a 00 56 e8 ?? ?? ?? ?? ff 35 b0 80 43 00 ff 35 b8 80 43 00 56 e8 ?? ?? ?? ?? 83 c4 1c 8d 45 bc 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_ORB_2147966937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.ORB!MTB"
        threat_id = "2147966937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 7d e4 1e 7d 2a 8b 4d e0 33 4d dc 03 4d e4 89 4d e0 8b 55 dc 23 55 e0 8b 45 e4 d1 e0 0b d0 89 55 dc 83 7d e4 0f 75 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRat_APR_2147968029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.APR!AMTB"
        threat_id = "2147968029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "D:\\vs2012\\project\\myf\\Release\\myf.pdb" ascii //weight: 15
        $x_3_2 = "ocuments and Settings\\All Users\\Documents\\xqowmwew.exe" ascii //weight: 3
        $x_2_3 = "/c timeout /t 4 /nobreak && del /f /q \"%s\"" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

