rule Trojan_Win32_Azorult_A_2147730784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.A"
        threat_id = "2147730784"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gigorerivekekari saruginilevusubonaxiwi yovizi" ascii //weight: 1
        $x_1_2 = "nukisihini.txt" ascii //weight: 1
        $x_1_3 = "bepuhuguwujejixafupacelunu.jpg" ascii //weight: 1
        $x_1_4 = "yifunogaceboracoye.txt" ascii //weight: 1
        $x_1_5 = "kuluyesepuhe zimosafodi dusepejacudagemuvafalomi" ascii //weight: 1
        $x_1_6 = "seyicuwatita.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Azorult_B_2147732004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.B"
        threat_id = "2147732004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 55 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {4c 00 65 00 67 00 61 00 6c 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 a9 00 20 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 20 00 49 00 6e 00 63 00 2e 00 2c 00 20 00 32 00 30 00 30 00 37 00 13 20 32 00 30 00 31 00 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_2147741256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult!ibt"
        threat_id = "2147741256"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c7 07 3c 00 00 00 8d 45 80 89 47 04 c7 47 08 20 00 00 00 8d 85 80 fe ff ff 89 47 10 c7 47 14 00 01 00 00 8d 85 00 fe ff ff 89 47 1c c7 47 20 80 00 00 00 8d 85 80 fd ff ff 89 47 24 c7 47 28 80 00 00 00 8d 85 80 f5 ff ff 89 47 2c c7 47 30 00 08 00 00 8d 85 80 f1 ff ff 89 47 34 c7 47 38 00 04 00 00 57 68 00 00 00 90 8b 45 cc}  //weight: 10, accuracy: High
        $x_10_2 = "SELECT DATETIME( ((visits.visit_time/1000000)-11644473600),\"unixepoch\")" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_DS_2147741403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.DS!MTB"
        threat_id = "2147741403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 53 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 83 2d ?? ?? ?? ?? 01 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 e8 ?? ?? ?? ?? 4b 10 00 bb ?? ?? ?? 00 [0-16] 75}  //weight: 1, accuracy: Low
        $x_1_3 = {5a 59 59 64 89 10 68 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_DX_2147741739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.DX!MTB"
        threat_id = "2147741739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 03 8a 0c 10 8a 5c 10 01 8a 6c 10 02 8a 54 10 03 88 55 0b c0 65 0b 02 8a 45 0b 24 c0 0a c8 8a c2 c0 e0 06 80 e2 fc 88 45 0b 0a e8 8b 45 f0 c0 e2 04 0a d3 88 0c 06 88 54 06 01 83 c6 02 89 75 f8 88 2c 06 8d 4d f8 e8 [0-8] 8b 55 f4 03 55 fc 8b 75 f8 8b 5d ec 89 55 f4 3b 17 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_PA_2147742422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.PA!MTB"
        threat_id = "2147742422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 cb 89 4c 24 10 8b 4c 24 18 03 c8 c1 e8 05 89 44 24 14 8b 44 24 2c 01 44 24 14 8b 44 24 10 33 c1 31 44 24 14 81 3d ?? ?? ?? ?? ba 05 00 00 89 44 24 10 c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_PA_2147742422_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.PA!MTB"
        threat_id = "2147742422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 c4 ?? 89 55 ?? 89 45 ?? [0-10] c6 45 ?? ?? [0-10] 8b 45 ?? 89 45 ?? [0-10] 8b 45 ?? 8a 80 ?? ?? ?? ?? 32 45 ?? 8b 55 ?? 88 02 [0-10] 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 e0 89 45 ?? [0-16] 8b 45 ?? 89 45 ?? [0-16] 8b 45 ?? 01 45 ?? [0-16] 8b 55 ?? 8b 45 ?? e8 ?? ?? ?? ?? ff 45 ?? 81 7d ?? ?? ?? 00 00 75}  //weight: 1, accuracy: Low
        $x_1_3 = {55 8b ec 83 c4 ?? 89 ?? f8 [0-5] 89 45 fc [0-10] c6 45 ?? ?? [0-10] 8b 45 fc 89 45 ?? [0-10] 8b 45 ?? 8a 80 ?? ?? ?? ?? [0-16] 32 45 ?? [0-16] 8b ?? f8 [0-5] 88 ?? [0-10] 8b e5 5d}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 e4 89 45 ?? [0-10] 8b 45 ?? 89 45 ?? [0-10] 8b 45 ?? 01 45 ?? [0-10] e8 ?? ?? ?? ?? 50 8b 4d ?? [0-10] e8 ?? ?? ?? ?? ff 45 ?? 81 7d ?? ?? ?? 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Azorult_FR_2147742711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.FR!MTB"
        threat_id = "2147742711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ST234LMUV56CklAopq78Brstuvwxyz01NOPQRmGHIJKWXYZabcdefgDEFhijn9+/" ascii //weight: 1
        $x_1_2 = "SYSInfo.txt" ascii //weight: 1
        $x_1_3 = "CookieList.txt" ascii //weight: 1
        $x_1_4 = "Passwords.txt" ascii //weight: 1
        $x_1_5 = {85 c0 74 40 85 d2 74 31 53 56 57 89 c6 89 d7 8b 4f fc 57}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_FS_2147742780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.FS!MTB"
        threat_id = "2147742780"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MIOSHJD-VBDIS-HUIDV-DQEFDD" ascii //weight: 1
        $x_1_2 = "Comp(User) :" wide //weight: 1
        $x_1_3 = "[Programms]" wide //weight: 1
        $x_1_4 = "wallet_path" wide //weight: 1
        $x_1_5 = "%APPDATA%\\Skype" wide //weight: 1
        $x_1_6 = "Software\\Bitcoin\\Bitcoin-Qt" wide //weight: 1
        $x_1_7 = "/c timeout 1 & del \"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_SF_2147742824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.SF!MTB"
        threat_id = "2147742824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 40 6b c0 00 c6 80 ?? ?? ?? ?? 6b 33 c0 40 6b c0 0a c6 80 ?? ?? ?? ?? 6c 33 c0 40 6b c0 06 c6 80 ?? ?? ?? ?? 33 33 c0 40 6b c0 03 c6 80 ?? ?? ?? ?? 6e 33 c0 40 c1 e0 02 c6 80 ?? ?? ?? ?? 65}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 04 58 6b c0 00 8b 4d ?? 8b 04 01 89 45 ?? 6a 04 58 c1 e0 00 8b 4d ?? 8b 04 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_AX_2147743759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.AX!MTB"
        threat_id = "2147743759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PasswordsList.txt" ascii //weight: 1
        $x_1_2 = "scr.jpg" ascii //weight: 1
        $x_1_3 = "ip.txt" ascii //weight: 1
        $x_1_4 = "System.txt" ascii //weight: 1
        $x_1_5 = ".address.txt" ascii //weight: 1
        $x_1_6 = "%APPDATA%\\Skype" ascii //weight: 1
        $x_1_7 = "353E77DF-928B-4941-A631-512662F0785A3061-4E40-BBC2-3A27F641D32B-54FF-44D7-85F3-D950F519F12F" ascii //weight: 1
        $x_1_8 = "Computer(Username) :" ascii //weight: 1
        $x_1_9 = "Screen:" ascii //weight: 1
        $x_1_10 = "[Soft]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Win32_Azorult_AY_2147743769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.AY!MTB"
        threat_id = "2147743769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 c4 f8 89 55 f8 89 45 fc 90 [0-16] 8b 7d fc ff 75 f8 01 3c 24 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d0 32 8e ?? ?? ?? 00 88 0a [0-16] 5e c3 30 00 56 [0-16] 8b f2 [0-16] 03 c6 [0-16] 8b d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_AX_2147743773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.AX!!Azorult.gen!A"
        threat_id = "2147743773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "Azorult: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PasswordsList.txt" ascii //weight: 1
        $x_1_2 = "scr.jpg" ascii //weight: 1
        $x_1_3 = "ip.txt" ascii //weight: 1
        $x_1_4 = "System.txt" ascii //weight: 1
        $x_1_5 = ".address.txt" ascii //weight: 1
        $x_1_6 = "%APPDATA%\\Skype" ascii //weight: 1
        $x_1_7 = "353E77DF-928B-4941-A631-512662F0785A3061-4E40-BBC2-3A27F641D32B-54FF-44D7-85F3-D950F519F12F" ascii //weight: 1
        $x_1_8 = "Computer(Username) :" ascii //weight: 1
        $x_1_9 = "Screen:" ascii //weight: 1
        $x_1_10 = "[Soft]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule Trojan_Win32_Azorult_BZ_2147744036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.BZ!MTB"
        threat_id = "2147744036"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 c8 70 72 6c 20 c7 45 cc 68 79 70 65 c7 45 d0 72 76 20 20 e9}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 d4 58 65 6e 56 c7 45 d8 4d 4d 58 65}  //weight: 1, accuracy: High
        $x_1_3 = {8b ce c1 e1 05 8b fe c1 ef 02 03 cf 0f be 3a 03 cf 33 f1 42 48 e9 38 26 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {56 8b f1 85 f6 0f 84 1e 00 00 00 33 c9 41 2b c8 57 8b 7c 24 0c 8d 14 01 83 e2 0f 8a 14 3a 30 10 40 4e 0f 85 e9 ff ff ff 5f 5e c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_BZ_2147744036_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.BZ!MTB"
        threat_id = "2147744036"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8a 45 ff 8a 4d fe 24 c0 08 45 fc 8b 45 f8 88 0c 07 8a 4d fd 88 4c 07 01 83 0d}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_PB_2147744391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.PB!MTB"
        threat_id = "2147744391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {bf 06 f8 e5 c2 81 fe 87 0d 00 00 0f 44 c7 8b fa a3 ?? ?? ?? ?? 8b 45 ?? c1 ef 05 03 c1 03 7d ?? 33 f8 8b 45 ?? 03 c2 33 f8 81 fe 98 05 00 00 75}  //weight: 20, accuracy: Low
        $x_1_2 = {89 5d f0 8b 03 89 45 fc 57 8b fa 81 fe 64 09 00 00 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_PC_2147744522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.PC!MTB"
        threat_id = "2147744522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 83 c0 01 89 45 fc 83 7d fc 04 73 ?? 8b 45 fc 33 d2 b9 04 00 00 00 f7 f1 (8b 45 ??|8b 85 ?? ?? ?? ??) 0f be 0c 10 8b 55 fc 0f b6 44 15 ?? 33 c1 8b 4d fc 88 44 0d ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d fc 83 c1 01 89 4d fc 81 7d fc ?? ?? 00 00 73 ?? 8b 45 fc 33 d2 b9 04 00 00 00 f7 f1 (8b 45 ??|8b 85 ?? ?? ?? ??) 0f be 0c 10 8b 55 fc 0f b6 [0-6] 33 c1 8b 4d fc 88 [0-6] eb}  //weight: 1, accuracy: Low
        $x_1_3 = {83 7d e0 04 0f 83 ?? ?? ?? ?? 8b 45 ?? 8b 4d e0 83 e1 03 0f be 04 08 8b 4d e0 0f b6 54 0d ?? 31 c2 88 d3 88 5c 0d ?? 8b 45 e0 83 c0 01 89 45 e0 e9}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 d4 8b 4d e0 83 e1 03 0f be 04 08 8b 4d e0 0f b6 14 0d ?? ?? ?? ?? 31 c2 88 d3 88 1c 0d ?? ?? ?? ?? 8b 45 e0 83 c0 01 89 45 e0 e9}  //weight: 1, accuracy: Low
        $x_1_5 = {ff 83 c0 01 89 85 ?? ?? ?? ff 83 bd ?? ?? ?? ff 04 73 2f 8b 85 ?? ?? ?? ff 33 d2 b9 04 00 00 00 f7 f1 8b 45 ?? 0f be 0c 10 8b 95 ?? ?? ?? ff 0f b6 44 15 ?? 33 c1 8b 8d ?? ?? ?? ff 88 44 0d f8 eb 05 00 8b 85}  //weight: 1, accuracy: Low
        $x_1_6 = {ff 83 c2 01 89 95 ?? ?? ?? ff 81 bd ?? ?? ?? ff ?? ?? 00 00 73 35 8b 85 ?? ?? ?? ff 33 d2 b9 04 00 00 00 f7 f1 8b 45 ?? 0f be 0c 10 8b 95 ?? ?? ?? ff 0f b6 84 15 ?? ?? ?? ff 33 c1 8b 8d ?? ?? ?? ff 88 84 0d ?? ?? ?? ff eb 05 00 8b 95}  //weight: 1, accuracy: Low
        $x_1_7 = {83 c1 01 89 4d ?? 83 7d ?? 04 73 ?? 8b 45 ?? 33 d2 b9 04 00 00 00 f7 f1 8b 45 ?? 0f be 0c 10 8b 55 ?? 0f b6 44 15 ?? 33 c1 8b 4d ?? 88 44 0d ?? eb 03 00 8b 4d}  //weight: 1, accuracy: Low
        $x_1_8 = {83 c1 01 89 4d ?? 81 7d ?? ?? ?? 00 00 73 ?? 8b 45 ?? 33 d2 b9 04 00 00 00 f7 f1 8b 45 ?? 0f be 0c 10 8b 55 ?? 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d ?? 88 81 ?? ?? ?? ?? eb 03 00 8b 4d}  //weight: 1, accuracy: Low
        $x_1_9 = {ba 01 00 00 00 6b d2 03 0f b6 44 15 ?? b9 01 00 00 00 6b c9 03 0f b6 54 0d ?? 3b c2 75 ?? b8 01 00 00 00 c1 e0 00 0f b6 4c 05 ?? ba 01 00 00 00 c1 e2 00 0f b6 44 15 ?? 3b c8 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Azorult_FW_2147744884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.FW!MTB"
        threat_id = "2147744884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 01 00 00 00 c3 55 8b ec 8d 45 c4 83 ec 3c 50 e8 0d 00 00 00 8d 45 c4 50 e8 88 07 00 00 59 59 c9 c3 55 8b ec 83 ec 38 53 56 57 8b 45 08 c6 00 00 83 65 fc 00 e8 00 00 00 00 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_PR_2147745101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.PR!MTB"
        threat_id = "2147745101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 38 8a 44 38 01 88 4c 24 18 88 44 24 13 75 ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 45 00 8a 4c 38 03 8a d1 c0 e2 06 0a 54 38 02 8a c1 24 f0 80 e1 fc c0 e0 02 83 c7 04 0a 44 24 18 c0 e1 04 0a 4c 24 13 88 04 1e 88 4c 1e 01 8b 4c 24 1c 88 54 1e 02 83 c6 03 3b 39 72}  //weight: 1, accuracy: Low
        $x_1_2 = {56 57 8b 7c 24 10 33 f6 85 ff 7e 13 53 8b 5c 24 10 e8 ?? ?? ?? ?? 30 04 1e 46 3b f7 7c f3 5b 5f 5e c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_FX_2147745159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.FX!MTB"
        threat_id = "2147745159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 0c be ?? ?? ?? ?? 57 57 57 57 57 57 ff 15 ?? ?? ?? ?? 4e 75 f1 e8 07 00 00 00 5f 33 c0 5e c2 10 00}  //weight: 1, accuracy: Low
        $x_1_2 = {7c df c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 50 00 00 8b f3 05 ?? ?? ?? ?? a3 ?? ?? ?? 00 81 fe ?? ?? ?? 00 75 10 68 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 a3 ?? ?? ?? 00 46 81 fe ?? ?? ?? 00 7c df c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? c7 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_GJ_2147745255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.GJ!MTB"
        threat_id = "2147745255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ff 8d 77 01 8b c7 83 e0 03 8d 4e fe 8a 5c 05 f8 30 9c 3d ?? ?? ff ff 8b c6 83 e0 03 83 c6 06 8a 54 05 f8 30 94 3d ?? ?? ff ff 8d 41 ff 83 e0 03 83 e1 03 8a 44 05 f8 30 84 3d ?? ?? ff ff 8a 44 0d f8 30 84 3d ?? ?? ff ff 30 9c 3d ?? ?? ff ff 30 94 3d ?? ?? ff ff 83 c7 06 81 fe ?? ?? 00 00 72 a2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_GH_2147745337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.GH!MTB"
        threat_id = "2147745337"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 5c 24 0e 8a 54 24 0f 8a c5 8a e1 34 ?? 80 f4 ?? 80 f3 ?? 80 f2 ?? 3c ?? 75 0e 80 fc ?? 75 09 80 fb ?? 75 04 84 d2 74 07 41 89 4c 24 0c eb d0}  //weight: 1, accuracy: Low
        $x_1_2 = {33 ff 8d 77 01 8d 9b 00 00 00 00 8b c7 83 e0 03 8d 4e fe 8a 5c ?? ?? 30 5c 3c ?? 30 5c 3c ?? 8b c6 83 e0 03 83 c6 06 8a 54 04 0c 30 54 3c ?? 30 54 3c ?? 8d 41 ff 83 e0 03 83 e1 03 8a 44 04 0c 30 44 3c 12 8a 44 0c 0c 30 44 3c 13 83 c7 06 81 fe e3 02 00 00 72 b4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_PD_2147745573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.PD!MTB"
        threat_id = "2147745573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8b c7 8d b5 ?? ?? ff ff 83 e0 03 03 f7 83 c7 06 8a 54 05 f8 8d 04 0e 30 16 83 e0 03 30 56 04 8a 4c 05 f8 8d 43 ff 30 4e 01 83 e0 03 30 4e 05 8b 8d ?? ?? ff ff 8a 44 05 f8 30 46 02 8b c3 83 e0 03 83 c3 06 8a 44 05 f8 30 46 03 81 ff ?? ?? 00 00 72}  //weight: 20, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_SN_2147745722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.SN!MTB"
        threat_id = "2147745722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 6a 00 [0-16] 53 81 ff ?? ?? 00 00 75 ?? [0-32] 81 3d ?? ?? ?? ?? ?? ?? 00 00 75 ?? [0-21] 8b 15 ?? ?? ?? ?? 69 d2 ?? ?? ?? 00 89 15 ?? ?? ?? ?? 81 05 ?? ?? ?? 00 ?? ?? ?? 00 81 3d ?? ?? ?? 00 ?? ?? 00 00 0f b7 1d ?? ?? ?? ?? 75 ?? [0-16] 30 1c 2e 46 3b f7 7c ?? 5b 5f 5e 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_PE_2147745827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.PE!MTB"
        threat_id = "2147745827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c3 fc 3b 5c 24 10 7c 54 8b 5c 24 ?? 03 5c 24 10 89 5c 24 14 8b 5c 24 04 03 5c 24 0c 89 5c 24 18 ff 74 24 14 90 [0-10] 5f 50 58 ff 74 24 18 90 [0-10] 5e 89 c0 8a 2f 90 [0-10] 8a 0e 50 88 e8 30 c8 88 07 58 ff 44 24 0c 8b 5c 24 0c 3b 5c 24 08 7e 08 c7 44 24 0c 00 00 00 00 83 44 24 10 04 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_GK_2147745854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.GK!MTB"
        threat_id = "2147745854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e9 14 01 00 00 56 57 51 8b 74 24 14 8b 7c 24 10 8b 4c 24 18 f3 a4 59 5f 5e c2 0c 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d 08 33 d2 8b c6 f7 75 0c 8a 04 0a ba ?? ?? 00 00 30 04 37 46 3b f2 72 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_PF_2147745855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.PF!MTB"
        threat_id = "2147745855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c2 01 89 95 ?? ?? ?? ?? 81 bd ?? ?? ?? ?? e2 02 00 00 73 36 8b 85 ?? ?? ?? ?? 33 d2 b9 04 00 00 00 f7 f1 8b 85 ?? ?? ?? ?? 0f be 0c 10 8b 95 ?? ?? ?? ?? 0f b6 82 ?? ?? ?? 00 33 c1 8b 8d ?? ?? ?? ?? 88 81 ?? ?? ?? 00 eb af 06 00 8b 95}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c1 01 89 8d ?? ?? ?? ?? 83 bd ?? ?? ?? ?? 04 73 32 8b 85 ?? ?? ?? ?? 33 d2 b9 04 00 00 00 f7 f1 8b 85 ?? ?? ?? ?? 0f be 0c 10 8b 95 ?? ?? ?? ?? 0f b6 44 15 ?? 33 c1 8b 8d ?? ?? ?? ?? 88 44 0d ?? eb b6 06 00 8b 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_YP_2147745861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.YP!MTB"
        threat_id = "2147745861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c9 fd 43 03 00 89 0d ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 81 3d ?? ?? ?? ?? cf 12 00 00 0f b7 1d ?? ?? ?? ?? 75 0a 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 45 f8 30 1c 06 46 3b f7 7c 8e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_PG_2147746021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.PG!MTB"
        threat_id = "2147746021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 6c 03 45 60 89 45 54 8b 4d 6c c1 e9 05 89 4d 70 8b 55 70 03 55 4c 89 55 70 8b 45 74 33 45 54 89 45 74 c7 05 ?? ?? ?? ?? f4 6e e0 f7 8b 4d 74 33 4d 70 89 4d 70}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 04 00 00 00 6b c2 00 8b 4d 64 8b 14 01 89 55 48 b8 04 00 00 00 c1 e0 00 8b 4d 64 8b 14 01 89 55 44 b8 04 00 00 00 d1 e0 8b 4d 64 8b 14 01 89 55 50 81 3d ?? ?? ?? ?? 85 0f 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_GS_2147746214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.GS!MTB"
        threat_id = "2147746214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 74 24 14 [0-16] 5f 50 58 ff 74 24 18 [0-16] 5e 89 c0 8a 2f [0-16] 8a 0e 50 88 e8 30 c8 88 07 58 ff 44 24 0c 8b 5c 24 0c 3b 5c 24 08 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_GT_2147746222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.GT!MTB"
        threat_id = "2147746222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 95 a0 fb ff ff 83 c2 01 89 95 a0 fb ff ff 81 bd a0 fb ff ff ?? ?? 00 00 73 2d 8b 85 a0 fb ff ff 33 d2 f7 75 0c 8b 45 08 0f be 0c 10 8b 55 d4 03 95 a0 fb ff ff 0f b6 02 33 c1 8b 4d d4 03 8d a0 fb ff ff 88 01 eb b8 8b 55 d4}  //weight: 1, accuracy: Low
        $x_1_2 = {56 57 51 8b 74 24 14 8b 7c 24 10 8b 4c 24 18 f3 a4 59 5f 5e c2 0c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_DSK_2147747901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.DSK!MTB"
        threat_id = "2147747901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 45 fc 43 94 0e 00 81 45 fc 7e 0a 18 00 69 0d ?? ?? ?? ?? fd 43 03 00 8b 45 fc 83 c0 02 03 c1 a3}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 44 24 10 8b 54 24 14 33 c6 c7 05 ?? ?? ?? ?? ca e3 40 df 8b 74 24 28 81 c2 47 86 c8 61 2b d8 89 54 24 14 83 ef 01 0f 85}  //weight: 2, accuracy: Low
        $x_2_3 = {8a 8c 3e f5 d0 00 00 8b 15 ?? ?? ?? ?? 88 0c 32 8b 4d fc 5f 33 cd 5e e8 ?? ?? ?? ?? 8b e5 5d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Azorult_A_2147748040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.A!!Azorult.gen!A"
        threat_id = "2147748040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "Azorult: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PasswordsList.txt" wide //weight: 1
        $x_1_2 = "%appdata%\\Electrum\\wallets\\" wide //weight: 1
        $x_1_3 = "%appdata%\\Electrum-LTC\\wallets\\" wide //weight: 1
        $x_1_4 = "%APPDATA%\\Ethereum\\keystore\\" wide //weight: 1
        $x_1_5 = "%APPDATA%\\Exodus\\" wide //weight: 1
        $x_1_6 = "%APPDATA%\\Jaxx\\Local Storage\\" wide //weight: 1
        $x_1_7 = "%APPDATA%\\MultiBitHD\\" wide //weight: 1
        $x_1_8 = "%appdata%\\Telegram Desktop\\tdata\\" wide //weight: 1
        $x_1_9 = "Software\\monero-project\\monero-core" wide //weight: 1
        $x_1_10 = "Software\\Bitcoin\\Bitcoin-Qt" wide //weight: 1
        $x_1_11 = "\\Sessions\\1\\BaseNamedObjects\\frenchy_shellcode_006" wide //weight: 1
        $x_1_12 = "scr.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_AA_2147748469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.AA!MTB"
        threat_id = "2147748469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 85 c0 46 3d ?? ?? ?? ?? ff 37 3d ?? ?? ?? ?? 59 81 ff ?? ?? ?? ?? e8 ?? ?? 00 00 85 ff 39 c1 75}  //weight: 1, accuracy: Low
        $x_1_2 = {51 66 81 fa ?? ?? 31 34 24 66 81 fa ?? ?? 59 66 85 db c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_AA_2147748469_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.AA!MTB"
        threat_id = "2147748469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 85 ff ?? ?? 81 ff ?? ?? 00 00 75 0a 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 69 d2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? ?? ?? ?? ?? a0 ?? ?? ?? ?? 30 04 1e 46 3b f7 7c c5}  //weight: 1, accuracy: Low
        $x_1_2 = {51 6a 00 ff 15 ?? ?? ?? ?? 8a 94 3e ?? ?? ?? ?? a1 ?? ?? ?? ?? 88 14 30 5f 8b 4d fc 33 cd e8 ?? ?? ?? ?? 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_PH_2147748485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.PH!MTB"
        threat_id = "2147748485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8a 88 ?? ?? ?? 00 f6 d1 2a c8 80 c1 02 80 f1 a2 80 e9 64 f6 d1 fe c9 88 88 ?? ?? ?? 00 40 83 f8 09 72}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c2 8d 44 10 01 35 a4 00 00 00 2b c2 83 c0 47 8b c8 c1 e9 03 c1 e0 05 83 e1 1f 0b c8 81 e1 ff 00 00 00 2b ca 8b c1 c1 e8 04 83 e0 0f c1 e1 04 0b c1 25 ff 00 00 00 2b c2 2d bf 00 00 00 33 c2 48 8b c8 c1 e9 03 80 e1 1f c0 e0 05 0a c8 88 8a ?? ?? ?? 00 42 83 fa 0f 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_GU_2147748502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.GU!MTB"
        threat_id = "2147748502"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {59 33 ff 33 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a 8b 5a 10 8b 12 75 db 8b c3 89 44 24 1c 61 c3}  //weight: 1, accuracy: High
        $x_1_2 = {89 45 f8 c6 45 dc 6e c6 45 dd 74 c6 45 de 64 c6 45 df 6c c6 45 e0 6c c6 45 e1 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_EX_2147748547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.EX!MTB"
        threat_id = "2147748547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 74 33 4d 70 89 4d 74 8b 55 6c 2b 55 74 89 55 6c 8b 45 60 2b 45 40 89 45 60 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? b9 ?? ?? ?? ?? 6b d1 ?? 8b 45 5c 8b 4d 6c 89 0c 10 ba ?? ?? ?? ?? c1 e2 ?? 8b 45 5c 8b 4d 68 89 0c 10 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 83 c5 ?? 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_V_2147749430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.V!MTB"
        threat_id = "2147749430"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 01 46 3b f3 7c 0b 00 8b 45 ?? 8d 0c 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_PVD_2147750849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.PVD!MTB"
        threat_id = "2147750849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 c8 33 d9 8b 55 08 03 55 0c 88 1a 8b 45 0c 83 e8 01 89 45 0c eb}  //weight: 2, accuracy: High
        $x_2_2 = {8a 1c 3e 8b 74 24 1c 32 1c 0e 88 7c 24 33 8b 4c 24 20 88 1c 39}  //weight: 2, accuracy: High
        $x_2_3 = {8b 44 24 10 33 c6 89 44 24 10 2b e8 8b 44 24 38 d1 6c 24 1c 29 44 24 14 ff 4c 24 28 0f 85}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Azorult_PVS_2147750973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.PVS!MTB"
        threat_id = "2147750973"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 c3 03 f0 81 e6 ff 00 00 00 81 3d ?? ?? ?? ?? 81 0c 00 00 5b 75 07 00 0f b6 b0}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 44 24 10 81 44 24 1c ?? ?? ?? ?? 33 c6 2b e8 ff 4c 24 24 89 44 24 10 0f 85}  //weight: 2, accuracy: Low
        $x_2_3 = {33 fa 8b cf b8 04 00 00 00 03 c1 83 e8 04 a3 06 00 8b 3d}  //weight: 2, accuracy: Low
        $x_2_4 = {8a 1c 0b 89 0c 24 8b 4c 24 20 32 1c 39 8b 7c 24 14 8b 0c 24 88 1c 0f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Azorult_PVK_2147751117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.PVK!MTB"
        threat_id = "2147751117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {25 ff 00 00 00 81 3d ?? ?? ?? ?? 21 06 00 00 a3 ?? ?? ?? ?? 75 0d 00 0f b6 81 ?? ?? ?? ?? 03 05}  //weight: 2, accuracy: Low
        $x_2_2 = {0f b6 d3 03 f2 81 e6 ff 00 00 00 81 3d ?? ?? ?? ?? 81 0c 00 00 75 07 00 0f b6 b0}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 44 24 10 81 44 24 1c ?? ?? ?? ?? 33 c6 2b e8 ff 4c 24 28 89 44 24 10 0f 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Azorult_GM_2147751284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.GM!MTB"
        threat_id = "2147751284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {81 ff 69 04 00 00 [0-16] 30 04 33 [0-16] 8d 44 24 ?? ?? 8d 4c 24 [0-6] 8d 54 24 [0-16] 46 3b f7 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RSV_2147751366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RSV!MTB"
        threat_id = "2147751366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f3 07 eb dd 13 81 6c 24 ?? ?? ?? ?? ?? b8 41 e5 64 03 81 6c 24 ?? ?? ?? ?? ?? 81 44 24 ?? ?? ?? ?? ?? 8b 4c 24 ?? 8b ?? d3 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_VSD_2147751600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.VSD!MTB"
        threat_id = "2147751600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 95 dc f3 ff ff 69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b c1 89 0d ?? ?? ?? ?? c1 e8 10 30 04 13 43 3b df 7c}  //weight: 2, accuracy: Low
        $x_2_2 = {8d 34 07 e8 ?? ?? ?? ?? 30 06 83 6d fc 01 8b 45 fc 85 c0 7d}  //weight: 2, accuracy: Low
        $x_2_3 = {31 7c 24 10 8b f5 c1 ee 05 03 74 24 38 81 3d ?? ?? ?? ?? b4 11 00 00 75 0a 00 c7 05}  //weight: 2, accuracy: Low
        $x_2_4 = {8b c7 f7 f3 8b 44 24 10 8a 04 02 30 01 47 3b 7c 24 18 0f 85}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Azorult_RVB_2147751787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RVB!MTB"
        threat_id = "2147751787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 3c 0a 39 ?? ?? ?? ?? ?? 81 f7 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 3c 08 ?? ?? ?? ?? ?? ?? 83 e9 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_SD_2147751975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.SD!MTB"
        threat_id = "2147751975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 00 00 00 00 58 89 c3 05 3a 05 00 00 81 c3 3a 0d 03 00 68 01 00 00 00 68 05 00 00 00 53 68 45 77 62 30 50 e8 04 00 00 00 83 c4 14 c3 83 ec 48 83 64 24 18 00 b9 4c 77 26 07 53 55 56 57 33 f6 e8 22 04 00 00 b9 49 f7 02 78 89 44 24 1c e8 14 04 00 00 b9 58 a4 53 e5 89 44 24 20 e8 06 04 00 00 b9 10 e1 8a c3 8b e8 e8 fa 03 00 00 b9 af b1 5c 94 89 44 24 2c e8 ec 03 00 00 b9 33 00 9e 95 89 44 24 30 e8 de 03 00 00 8b d8 8b 44 24 5c 8b 78 3c 03 f8 89 7c 24 10 81 3f 50 45 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_KMG_2147751999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.KMG!MTB"
        threat_id = "2147751999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 0c 16 a1 ?? ?? ?? ?? 46 c7 05 ?? ?? ?? ?? d8 53 2a 94 3b f0 72 ?? 33 f6 81 fe d8 e0 34 00 75 ?? e8 ?? ?? ?? ?? 46 81 fe 74 0f 4d 00 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_KMG_2147751999_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.KMG!MTB"
        threat_id = "2147751999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 48 07 00 00 75 ?? 89 3d ?? ?? ?? ?? 8b ce e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 46 3b f0 72}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 e1 bf 01 00 01 04 24 8b 04 24 8a 04 08 88 04 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_BS_2147752060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.BS!MTB"
        threat_id = "2147752060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 cb 89 8d ?? ?? ?? ?? 8b cb c1 e9 05 03 8d ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 31 85 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 72 07 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RL_2147753380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RL!MTB"
        threat_id = "2147753380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 c2 88 01 c3 8d 40 00 55 8b ec 51 53 56 57 6a ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 89 45 ?? 8b 7d ?? be ?? ?? ?? ?? bb ?? ?? ?? ?? 8b cf b2 ?? 8a 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RRI_2147753695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RRI!MTB"
        threat_id = "2147753695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 c7 04 24 00 00 00 00 81 2c 24 52 ef 6f 62 b8 41 e5 64 03 81 2c 24 68 19 2a 14 81 04 24 be 08 9a 76}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_KM_2147753726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.KM!MTB"
        threat_id = "2147753726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 fd 43 03 00 81 3d ?? ?? ?? ?? 9e 13 00 00 a3 ?? ?? ?? ?? 75 ?? 33 c0 50 50 50 ff 15 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 0f b7 05 ?? ?? ?? ?? 25}  //weight: 1, accuracy: Low
        $x_1_2 = {30 04 37 83 fb 19 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_KM_2147753726_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.KM!MTB"
        threat_id = "2147753726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 25 ff 00 00 00 8a 98 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 88 ?? ?? ?? ?? ?? 88 99 ?? ?? ?? ?? 0f b6 88 ?? ?? ?? ?? 0f b6 d3}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 34 38 e8 ?? ?? ?? ?? 30 06 b8 01 00 00 00 29 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 85 c0 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_AB_2147754298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.AB!MTB"
        threat_id = "2147754298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 49 40 0f 28 ca 0f 10 41 a0 66 0f ef c2 0f 11 41 a0 0f 10 41 b0 66 0f ef c8 0f 11 49 b0 0f 28 ca 0f 10 41 c0 66 0f ef c8 0f 11 49 c0 0f 10 41 d0 66 0f ef c2 0f 11 41 d0 83 ee 01 75 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_AD_2147754452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.AD!MTB"
        threat_id = "2147754452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 c9 89 4c 24 14 8d 64 24 00 81 f9 0d 04 00 00 75 0a}  //weight: 5, accuracy: High
        $x_5_2 = {33 c9 33 c0 8d 54 24 18 52 66 89 44 24 14 66 89 4c 24 16 8b 44 24 14}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_AD_2147754452_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.AD!MTB"
        threat_id = "2147754452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 85 ff 31 c9 3d ?? ?? ?? ?? 0b 0f 66 81 fb ?? ?? e8 ?? ?? ?? ?? e9 ?? ?? 00 00 [0-160] 81 fa ?? ?? ?? ?? 39 c1 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {56 66 81 ff ?? ?? 33 0c 24 85 db 5e 66 81 fb ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_SS_2147755773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.SS!MTB"
        threat_id = "2147755773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 0f 66 81 fb d7 53 [0-8] 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 00 8f 04 18 eb 0c}  //weight: 1, accuracy: High
        $x_1_3 = "K6JGwjI8ehO366lL9wyXu4t77" wide //weight: 1
        $x_1_4 = "Planimetrical8" wide //weight: 1
        $x_1_5 = "Pensionerings9" wide //weight: 1
        $x_1_6 = "Halshugning5" wide //weight: 1
        $x_1_7 = "kanoniseringernes" wide //weight: 1
        $x_1_8 = "Geomagnetism4" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_F_2147759959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.F!MTB"
        threat_id = "2147759959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gP7EzedLfnpwhHvg9ZcM6OQLC8AD0fEvtR207" wide //weight: 1
        $x_1_2 = "XoRCBQHSNCvgtgK98B5ryABHJyrf7vCS205" wide //weight: 1
        $x_1_3 = "XbCKWNikAV0e53322qvckq42k3vXdR1OCX7Iyk0" wide //weight: 1
        $x_1_4 = "XcDdwoGziOnRw5WgesHEpbT2weOpc25J9Nf9242" wide //weight: 1
        $x_1_5 = "vlq7fnSnPMrEpdU6JrSuSkxP4d40" wide //weight: 1
        $x_1_6 = "BkJ0f4RReHsULdPjfXenyRfnAQr251" wide //weight: 1
        $x_1_7 = "CTfgVZ3MOisRZLq52C3R6xc5LQA89e37mu2d3zo32" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Azorult_SK_2147765093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.SK!MSR"
        threat_id = "2147765093"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 95 78 fd ff ff 03 55 fc 8b 85 74 fd ff ff 03 45 fc 8a 88 3b 2d 0b 00 88 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_MR_2147772259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.MR!MTB"
        threat_id = "2147772259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d9 33 d8 89 [0-3] 89 [0-5] 89 [0-5] 8b [0-5] 29 [0-3] 81 3d [0-8] 8b [0-5] 29 [0-3] ff [0-5] 8b [0-3] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_MS_2147772347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.MS!MTB"
        threat_id = "2147772347"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e3 8b c6 c1 e8 05 03 [0-5] 03 [0-5] 8d [0-3] 33 ?? 33 ?? 33 ?? 89 ?? ?? 89 [0-5] 89 [0-5] 8b [0-5] 29 [0-3] 81 3d [0-8] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_2147772557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.MT!MTB"
        threat_id = "2147772557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 03 [0-5] 03 [0-5] 8d [0-2] 33 ?? 33 ?? 89 [0-2] 89 [0-5] 89 [0-5] 8b [0-5] 29 [0-2] 81 3d [0-8] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_MU_2147772861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.MU!MTB"
        threat_id = "2147772861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 05 03 [0-5] 03 [0-5] 03 ?? 33 ?? 33 ?? 89 [0-2] 89 [0-5] 89 [0-5] 8b [0-5] 29 [0-2] 81 3d [0-8] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RW_2147773468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RW!MTB"
        threat_id = "2147773468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 2e eb ed 8b ?? ?? 8b c6 d3 e8 8b ?? ?? c7 ?? ?? ?? ?? ?? 2e ce 50 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RW_2147773468_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RW!MTB"
        threat_id = "2147773468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 fe 93 8d 6a 33 ?? 31 ?? ?? 8b ?? ?? 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RW_2147773468_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RW!MTB"
        threat_id = "2147773468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 89 4c ?? ?? 8d [0-5] e8 ?? ?? ?? ?? 81 [0-10] 8b [0-30] fc 03 cf ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RW_2147773468_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RW!MTB"
        threat_id = "2147773468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 eb c7 05 ?? ?? ?? ?? ee 3d ea f4 03 9d ?? ?? ?? ?? 33 da 81 3d ?? ?? ?? ?? b7 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RW_2147773468_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RW!MTB"
        threat_id = "2147773468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fc 03 cf ff 3c 00 [0-60] 05 03 ?? ?? 83 ?? ?? ?? ?? ?? 1b 89 [0-10] c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RW_2147773468_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RW!MTB"
        threat_id = "2147773468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ef 89 45 ?? c7 ?? ?? ?? ?? ?? 2e ce 50 91 89 ?? ?? 8b ?? ?? 01 ?? ?? 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RW_2147773468_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RW!MTB"
        threat_id = "2147773468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c6 47 86 c8 61 ff 8d ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 8b 45 ?? 5f 89 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RW_2147773468_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RW!MTB"
        threat_id = "2147773468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 03 45 ?? c7 05 ?? ?? ?? ?? b4 02 d7 cb 89 45 ?? 33 45 ?? c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RW_2147773468_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RW!MTB"
        threat_id = "2147773468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fc 03 cf ff 8b 32 00 [0-50] d3 ?? 89 ?? ?? 8b ?? ?? 01 ?? ?? c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RW_2147773468_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RW!MTB"
        threat_id = "2147773468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea c7 05 ?? ?? ?? ?? 2e ce 50 91 89 ?? ?? 8b ?? ?? 01 ?? ?? 81 ?? ?? ?? ?? ?? ff 03 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RW_2147773468_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RW!MTB"
        threat_id = "2147773468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 34 07 e8 ?? ?? ?? ?? 30 06 83 7d ?? 19 75 ?? 53 53 53 53 ff 15 ?? ?? ?? ?? 47 3b 7d ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RW_2147773468_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RW!MTB"
        threat_id = "2147773468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 e1 04 03 cb 8d 04 37 89 4c 24 ?? 8b d6 50 8d 4c 24 ?? c1 ea 05 51 c7 [0-5] b4 21 e1 c5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RW_2147773468_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RW!MTB"
        threat_id = "2147773468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 [0-5] 8b [0-10] 03 c1 8b [0-10] 33 [0-5] 83 3d [0-5] 27 c7 05 [0-5] 2e ce 50 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RW_2147773468_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RW!MTB"
        threat_id = "2147773468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e0 01 ?? ?? c7 ?? ?? ?? ?? ?? 84 cd 10 fe 8b ?? ?? 51 8d ?? ?? 52 e8 ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 91 05 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RW_2147773468_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RW!MTB"
        threat_id = "2147773468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 03 b5 ?? ?? ?? ?? 89 45 ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 8b 85 ?? ?? ?? ?? 03 c7 33 f0 81 3d ?? ?? ?? ?? 3f 0b 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RW_2147773468_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RW!MTB"
        threat_id = "2147773468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 89 55 ?? 8b 45 ?? 03 45 ?? 89 ?? ?? c7 ?? ?? ?? ?? ?? 82 cd 10 fe 8b ?? ?? 33 ?? ?? 89 ?? ?? 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RW_2147773468_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RW!MTB"
        threat_id = "2147773468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fe c3 14 0c 18 89 [0-5] 7c [0-5] 8b 35 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 33 c9 89 4c 24 ?? 8d 64 24 ?? 81 f9 0d 04 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RW_2147773468_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RW!MTB"
        threat_id = "2147773468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b fe 8b c7 c1 e0 04 03 45 ?? 03 cf 81 3d ?? ?? ?? ?? be 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 ea 05 03 55 ?? 50 8d 4d ?? 51 c7 05 ?? ?? ?? ?? b4 02 d7 cb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RW_2147773468_18
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RW!MTB"
        threat_id = "2147773468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 52 c0 5d 81 [0-9] 81 [0-9] 8b ?? ?? 8b ?? ?? 8b c2 d3 e0 89}  //weight: 1, accuracy: Low
        $x_1_2 = {40 2e eb ed 8b 4d ?? 03 cf 89 ?? ?? 8b ?? ?? 8b df d3 eb c7 ?? ?? ?? ?? ?? 2e ce 50 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Azorult_RW_2147773468_19
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RW!MTB"
        threat_id = "2147773468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 05 89 44 24 ?? 89 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8d 14 37 31 54 24 ?? 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 ea 05 89 4c 24 ?? 89 54 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b 44 24 ?? 8d 0c 37 33 c1 31 44 24 ?? 83 3d ?? ?? ?? ?? 42 c7 05 ?? ?? ?? ?? 36 06 ea e9 89 44 24 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Azorult_MV_2147773594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.MV!MTB"
        threat_id = "2147773594"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 c1 e0 04 03 ?? 33 [0-3] 33 [0-3] 2b ?? 81 [0-9] 8b [0-6] 29 [0-3] 83 [0-7] 0f [0-13] 89 ?? 5f 5e 5d 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RD_2147773716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RD!MTB"
        threat_id = "2147773716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ff 3b de 7e ?? 8b 8d ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 39 83 fb 19 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c5 89 45 ?? 8b 45 ?? 56 33 f6 57 89 85 ?? ?? ?? ?? 81 fb 2e 0f 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_GKM_2147773915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.GKM!MTB"
        threat_id = "2147773915"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {14 0f 3d 03 02 00 00 75 06 89 35 84 d1 7f 00 41 3b c8 72 14 00 8b 15 ?? ?? ?? ?? 8a 94 0a ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_GKM_2147773915_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.GKM!MTB"
        threat_id = "2147773915"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 c3 9e 26 00 a3 ?? ?? ?? ?? 0f b7 1d ?? ?? ?? ?? 81 e3 ff 7f 00 00 81 3d ?? ?? ?? ?? e7 08 00 00 75 [0-32] 30 1c ?? 83 ff 19 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_MW_2147774339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.MW!MTB"
        threat_id = "2147774339"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 01 83 fb ?? 47 3b fb 8b 45 08 8d [0-2] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_SM_2147775141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.SM!MSR"
        threat_id = "2147775141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 44 24 10 03 f5 8d 0c 3b 33 f1}  //weight: 1, accuracy: High
        $x_1_2 = {8b 84 24 38 04 00 00 8b 4c 24 14 89 78 04 5f 5e 5d 89 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_MX_2147775148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.MX!MTB"
        threat_id = "2147775148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 0c 1e 83 [0-2] 46 3b f7 a1 [0-4] 69 [0-5] 05 [0-4] a3 [0-4] 8a 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_MY_2147775280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.MY!MTB"
        threat_id = "2147775280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 1e 83 [0-2] 46 3b f7 a1 [0-4] 69 [0-5] 81 [0-5] a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_MZ_2147775684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.MZ!MTB"
        threat_id = "2147775684"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 06 83 fd ?? 47 3b fd 8b ?? ?? ?? 8d [0-2] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RDV_2147775818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RDV!MTB"
        threat_id = "2147775818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? 0f b7 1d ?? ?? ?? ?? 81 e3 ff 7f 00 00 81 3d ?? ?? ?? ?? e7 08 00 00 75 ?? 6a 00 6a 00 6a 00 e8 ?? ?? ?? ?? 30 1c 3e 83 fd 19 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_NA_2147776039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NA!MTB"
        threat_id = "2147776039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 7d ec 10 8d 4d d8 8b c3 8b b7 0c 01 00 00 0f 43 4d d8 33 d2 f7 75 e8 8a 04 0a 30 04 1e 43 8b 87 10 01 00 00 2b 87 0c 01 00 00 3b d8 75 d1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_NA_2147776039_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NA!MTB"
        threat_id = "2147776039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 3b 83 [0-3] 47 3b [0-2] a1 [0-4] 69 [0-5] 05 [0-4] a3 [0-4] 0f [0-6] 25 [0-4] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_NB_2147776528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NB!MTB"
        threat_id = "2147776528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 3b 7d 08 e8 [0-4] 30 [0-2] 83 [0-3] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {47 3b 7d 08 a1 [0-4] 69 [0-5] 81 [0-9] a3 [0-4] 81 [0-9] 0f [0-6] 25 [0-4] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ee 3d ea f4 03 [0-5] 33 [0-5] 89 [0-5] a3 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 fe 93 8d 6a 33 d1 31 ?? ?? 8b ?? ?? 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 e0 01 ?? ?? c7 ?? ?? ?? ?? ?? 84 cd 10 fe 8b ?? ?? 33 ?? ?? 89}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fb 61 36 13 01 0f [0-5] eb [0-5] a1 [0-4] a3 [0-4] 33 ff 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 ec 15 00 00 e8 ?? ?? ?? ?? 53 55 56 33 f6 81 3d ?? ?? ?? ?? 77 01 00 00 57 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e2 04 03 [0-5] 3d a9 0f 00 00 75 [0-5] c7 [0-5] 40 2e eb ed 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 89 55 ?? 8b ?? ?? 03 ?? ?? 89 ?? ?? c7 ?? ?? ?? ?? ?? fc 03 cf ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 89 55 ?? 8b ?? ?? 03 ?? ?? 89 ?? ?? c7 ?? ?? ?? ?? ?? fc 03 cf ff 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 05 03 54 24 ?? 50 c7 05 ?? ?? ?? ?? b4 21 e1 c5 c7 05 ?? ?? ?? ?? ff ff ff ff e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 2e eb ed 8b ?? ?? 8b fb d3 ef c7 ?? ?? ?? ?? ?? 2e ce 50 91 03 ?? ?? 3d eb 03 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e9 12 c9 23 00 89 ?? ?? 8b [0-25] c7 [0-5] fc 03 cf ff 81 [0-5] e3 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 89 45 ?? 8b ?? ?? 01 ?? ?? c7 ?? ?? ?? ?? ?? 84 cd 10 fe 8b ?? ?? 51 8d 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 45 ?? 33 c2 89 45 ?? 81 fb a3 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e0 01 ?? ?? c7 ?? ?? ?? ?? ?? 84 cd 10 fe 8b ?? ?? 81 ?? ?? ?? ?? ?? 7c 32 ef 01 01 ?? ?? ?? ?? ?? 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4d ?? 03 cb c7 05 ?? ?? ?? ?? 2e ce 50 91 03 45 ?? 33 c1 33 c7 83 ?? ?? ?? ?? ?? 27}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 45 e0 89 45 ?? c7 ?? ?? ?? ?? ?? 84 cd 10 fe 8b ?? ?? 33 ?? ?? 89 ?? ?? 8b ?? ?? 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c3 c1 ea 05 51 89 44 24 ?? c7 05 ?? ?? ?? ?? b4 21 e1 c5 c7 05 ?? ?? ?? ?? ff ff ff ff 03 d5 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e ce 50 91 e8 ?? ?? ?? ?? 8b [0-5] 8b ?? 8b ?? d3 ?? 03 [0-4] 33 ?? 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_18
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 fe 93 8d 6a 8b 55 ?? 33 d1 33 d3 8d 8d ?? ?? ?? ?? 89 55 ?? e8 ?? ?? ?? ?? 89 ?? ?? 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_19
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ec 1c 04 00 00 a1 ?? ?? ?? ?? 33 c4 89 84 24 ?? ?? ?? ?? a1 ?? ?? ?? ?? 56 57 8b 3d ?? ?? ?? ?? a3 ?? ?? ?? ?? 33 f6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_20
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 fe 93 8d 6a 8b ?? ?? ?? ?? ?? 33 c3 31 ?? ?? 8b ?? ?? 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 26 04 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_21
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e2 04 89 ?? ?? 8b ?? ?? 01 ?? ?? 8b ?? ?? 03 ?? ?? 89 ?? ?? 81 ?? ?? ?? ?? ?? 96 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_22
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 [0-4] 8b [0-5] 33 [0-5] 8b [0-10] 03 c1 33 c7 83 [0-10] 27 c7 [0-10] 2e ce 50 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_23
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 89 45 ?? 8b ?? ?? 01 ?? ?? c7 ?? ?? ?? ?? ?? 64 61 15 fe 8b ?? ?? 81 ?? ?? ?? ?? ?? 9c 9e ea 01 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_24
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d3 ea c7 05 ?? ?? ?? ?? 2e ce 50 91 89 55 ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 8b 4d ?? 33 cb 33 4d ?? 8d 85 ?? ?? ?? ?? 89}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_25
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 05 c7 05 ?? ?? ?? ?? 84 10 d6 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 81 3d ?? ?? ?? ?? c6 0e 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_26
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 93 8d 6a 8b [0-20] 03 cb 33 c1 31 [0-5] 81 [0-5] a3 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 ea 05 03 55 ?? 83 [0-5] 1b 8b c2 89 45 ?? c7 [0-5] fc 03 cf ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_27
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 89 45 ?? 8b ?? ?? 01 ?? ?? c7 ?? ?? ?? ?? ?? fc 03 cf ff 8b ?? ?? 51 8d}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 ea 89 55 ?? 8b ?? ?? 01 ?? ?? c7 ?? ?? ?? ?? ?? fc 03 cf ff 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_28
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ec b8 84 24 00 00 e8 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 77 01 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f0 29 75 ?? 51 c7 05 ?? ?? ?? ?? b4 02 d7 cb c7 05 ?? ?? ?? ?? ff ff ff ff e8 ?? ?? ?? ?? ff 4d ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_29
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 ?? c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 85 ?? ?? ?? ?? 01 45 ?? 81 3d ?? ?? ?? ?? 12 09 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 fe 93 8d 6a 33 ?? 31 ?? ?? 8b ?? ?? 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 26 04 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Azorult_RM_2147776922_30
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RM!MTB"
        threat_id = "2147776922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b fe 8b f7 [0-5] 04 03 ?? ?? 03 c7 81 [0-5] be 01 00 00 89}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f0 2b d6 [0-10] c7 [0-10] b4 02 d7 cb c7 [0-10] 89}  //weight: 1, accuracy: Low
        $x_1_3 = {33 f0 29 75 [0-10] c7 05 [0-10] b4 02 d7 cb c7 05 [0-5] ff ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Azorult_NC_2147777198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NC!MTB"
        threat_id = "2147777198"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 50 50 50 50 ff 15 [0-4] 46 3b f3 e8 [0-4] 30 [0-2] 83 [0-2] 75 [0-3] 50 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_ND_2147777417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.ND!MTB"
        threat_id = "2147777417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 37 83 [0-2] 46 3b f3 a1 [0-4] 69 [0-5] 81 3d [0-8] a3 [0-4] 81 [0-9] 56 0f [0-6] 81 [0-5] 81 [0-9] 8b ?? 5e c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_NE_2147777561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NE!MTB"
        threat_id = "2147777561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 81 ff [0-4] 0f [0-2] 46 3b f7 8a [0-6] 88}  //weight: 1, accuracy: Low
        $x_1_2 = {30 04 1f 47 3b ?? 81 fe [0-4] e8}  //weight: 1, accuracy: Low
        $x_2_3 = {30 04 1f 47 3b ?? 81 fe [0-4] 69 [0-9] 81 3d [0-8] a3 [0-4] 05 [0-4] a3 [0-4] c1 [0-2] 25 [0-4] c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Azorult_NF_2147777678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NF!MTB"
        threat_id = "2147777678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {30 06 47 3b fb 33 ?? 81 [0-5] 8b [0-3] 8d [0-2] e8}  //weight: 6, accuracy: Low
        $x_1_2 = {88 14 0f 3d [0-4] 75 06 89 [0-5] 41 3b c8 8b [0-5] 8a [0-6] 8b}  //weight: 1, accuracy: Low
        $x_1_3 = {5f 33 cd 5e e8 [0-4] c9 c3 0d 00 e8 [0-4] e8 [0-4] 8b 4d}  //weight: 1, accuracy: Low
        $x_1_4 = "GlobalAlloc" ascii //weight: 1
        $x_1_5 = "MapViewOfFile" ascii //weight: 1
        $x_1_6 = "SetEndOfFile" ascii //weight: 1
        $x_1_7 = "EqualSid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Azorult_NG_2147778120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NG!MTB"
        threat_id = "2147778120"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 01 46 3b f7 81 [0-5] 8b [0-3] 8d [0-2] a1 [0-4] 69 [0-5] 05 [0-4] a3 [0-4] 0f [0-6] 25 [0-4] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_NH_2147778181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NH!MTB"
        threat_id = "2147778181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 0c 8d [0-2] e8 [0-4] 30 ?? 47 3b fb 81 fb [0-4] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_NI_2147778319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NI!MTB"
        threat_id = "2147778319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 0c 3e 46 3b f3 81 [0-5] a1 [0-4] 69 [0-5] 05 [0-4] a3 [0-4] 8a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_NJ_2147778442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NJ!MTB"
        threat_id = "2147778442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 0c 02 8b 0d [0-4] 81 [0-5] 75 06 89 1d [0-4] 40 3b c1 8b 15 [0-4] 8a 8c 02 [0-4] 8b 15}  //weight: 1, accuracy: Low
        $x_1_2 = "SystemFunction036" ascii //weight: 1
        $x_1_3 = "GAIsProcessorFeaturePresent" ascii //weight: 1
        $x_1_4 = "SizeofResource" ascii //weight: 1
        $x_1_5 = "ERRORDIALOG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_NK_2147778444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NK!MTB"
        threat_id = "2147778444"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 0f 88 04 0e 81 fa [0-4] 75 06 89 2d [0-4] 41 3b ca 72 e7}  //weight: 1, accuracy: Low
        $x_1_2 = "ScrollConsoleScreenBufferW" ascii //weight: 1
        $x_1_3 = "GetCommMask" ascii //weight: 1
        $x_1_4 = "SystemFunction036" ascii //weight: 1
        $x_1_5 = "GAIsProcessorFeaturePresent" ascii //weight: 1
        $x_1_6 = "SizeofResource" ascii //weight: 1
        $x_1_7 = "ERRORDIALOG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_NL_2147778735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NL!MTB"
        threat_id = "2147778735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 0c 33 83 [0-2] 46 3b f7 81 ff [0-4] 81 3d [0-8] a1 [0-4] 69 [0-5] 05 [0-4] a3 [0-4] 8a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_NM_2147779098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NM!MTB"
        threat_id = "2147779098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 0c 32 3d [0-4] 46 3b f0 72 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 6a 00 6a 00 ff 15 [0-4] 6a 00 ff 15 [0-4] a1 [0-4] 3d [0-4] e8 [0-4] 81 3d [0-8] 8b 3d [0-4] 8b 1d [0-4] 33 f6 81 3d [0-8] 81 fe [0-4] 81 3d [0-8] 46 81 fe [0-4] 7c b9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_NN_2147779694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NN!MTB"
        threat_id = "2147779694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 1e 83 ff 19 75 0e 6a 00 6a 00 6a 00 6a 00 ff 15 [0-4] 46 3b f7 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {30 04 33 83 ?? ?? 46 3b f7 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Azorult_NO_2147779719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NO!MTB"
        threat_id = "2147779719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 81 ec [0-4] a1 [0-4] 33 ?? 89 45 fc 56 33 f6 85 ff 7e 3d 8d [0-5] e8 [0-4] 30 [0-2] 83 [0-2] 46 3b f7 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_NP_2147779880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NP!MTB"
        threat_id = "2147779880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 0c 37 83 [0-2] 46 3b f3 a1 [0-4] 69 [0-5] 05 [0-4] a3 [0-4] 8a 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_NQ_2147779904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NQ!MTB"
        threat_id = "2147779904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 3b 83 [0-3] 47 3b 7d 08 81 7d [0-5] a1 [0-4] 69 [0-5] 05 [0-4] a3 [0-4] 0f [0-6] 25 [0-4] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_NR_2147779983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NR!MTB"
        threat_id = "2147779983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 3b 83 7d [0-2] 47 3b 7d 08 81 7d [0-5] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_NS_2147780049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NS!MTB"
        threat_id = "2147780049"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 14 8d [0-2] e8 [0-4] 30 ?? 83 ?? ?? 43 3b dd 81 fd [0-4] 75 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_NT_2147780162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NT!MTB"
        threat_id = "2147780162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 14 8d [0-2] e8 [0-4] 30 ?? 81 [0-5] 43 3b dd 81 [0-5] 75 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_NU_2147780356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NU!MTB"
        threat_id = "2147780356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 3b 81 [0-6] 47 3b 7d 08 81 [0-6] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_NV_2147780357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NV!MTB"
        threat_id = "2147780357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 4c 01 15 8b 15 [0-4] 88 [0-2] 8b [0-5] 81 [0-5] 75 0a c7 05 [0-8] 40 3b c1 72 ?? e8 [0-4] e8 [0-4] 33 ?? 3d [0-4] 40 3d [0-4] 7c ?? c7 05 [0-8] ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 4c 01 15 8b [0-5] 88 [0-2] 8b [0-5] 81 [0-5] 40 3b ?? 72 ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 [0-9] c7 05 [0-8] ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Azorult_EAN_2147780446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.EAN!MTB"
        threat_id = "2147780446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 0c 02 8b 0d ?? ?? ?? ?? 81 f9 03 02 00 00 75 0a c7 05 ?? ?? ?? ?? 74 19 00 00 40 3b c1 72 d0}  //weight: 10, accuracy: Low
        $x_5_2 = {30 04 3b 83 7d 08 19 75 1c 56}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Azorult_NW_2147780610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NW!MTB"
        threat_id = "2147780610"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 1e 81 [0-5] 46 3b f7 81 [0-5] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_NX_2147780849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NX!MTB"
        threat_id = "2147780849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 1e 81 [0-5] 46 3b f7 83 [0-2] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_NY_2147780894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NY!MTB"
        threat_id = "2147780894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 14 30 81 3d [0-8] 46 3b 35 [0-4] 8b [0-5] 8a [0-3] a1}  //weight: 1, accuracy: Low
        $x_1_2 = {88 14 30 81 3d [0-8] 46 3b [0-9] e8 [0-4] e8 [0-5] 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_NZ_2147780895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.NZ!MTB"
        threat_id = "2147780895"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 04 31 81 3d [0-8] 46 3b ?? ?? ?? ?? ?? 8b [0-5] 8a [0-3] 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {88 04 31 81 3d [0-8] 46 3b [0-9] e8 [0-4] e8 [0-4] 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_OA_2147781119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.OA!MTB"
        threat_id = "2147781119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c1 01 89 [0-5] 8b [0-5] 3b [0-5] 73 ?? a1 [0-4] 03 [0-5] 8b [0-5] 03 [0-5] 8a [0-2] 88 ?? 81 [0-9] [0-2] e8 [0-4] 68 [0-4] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RTH_2147781431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RTH!MTB"
        threat_id = "2147781431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ee 05 03 [0-5] 83 [0-5] 1b 8d [0-3] 89 [0-5] c7 05 [0-5] fc 03 cf ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RTH_2147781431_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RTH!MTB"
        threat_id = "2147781431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 fe 93 8d 6a 8b 85 ?? ?? ?? ?? 8d 0c 16 33 c1 31 45 ?? 81 3d [0-5] a3 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RTH_2147781431_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RTH!MTB"
        threat_id = "2147781431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e0 01 ?? ?? c7 ?? ?? ?? ?? ?? 84 cd 10 fe 8b ?? ?? 81 [0-9] 01 ?? ?? ?? ?? ?? 83 [0-9] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RTH_2147781431_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RTH!MTB"
        threat_id = "2147781431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d9 8b 4d ?? d3 ea c7 [0-10] 2e ce 50 91 03 55 ?? 33 d3 89 55 ?? 83 f8 27 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RTH_2147781431_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RTH!MTB"
        threat_id = "2147781431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e0 01 45 ?? c7 ?? ?? ?? ?? ?? 84 cd 10 fe 8b ?? ?? 81 [0-9] 01 ?? ?? ?? ?? ?? 8b ?? ?? 33 ?? ?? 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RTH_2147781431_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RTH!MTB"
        threat_id = "2147781431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 55 e0 89 55 ?? c7 05 ?? ?? ?? ?? 82 cd 10 fe 8b ?? ?? 81 05 ?? ?? ?? ?? 7e 32 ef 01 01 ?? ?? ?? ?? ?? 8b ?? ?? 33 05 ?? ?? ?? ?? 89 ?? ?? 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RTH_2147781431_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RTH!MTB"
        threat_id = "2147781431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 04 03 4d ?? 50 03 fe 8d 45 ?? 33 cf 50 c7 05 ?? b4 21 e1 c5}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 2c 19 00 00 e8 ?? ?? ?? ?? 56 33 f6 81 3d ?? ?? ?? ?? 77 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Azorult_RF_2147781555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RF!MTB"
        threat_id = "2147781555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e ce 50 91 03 45 ?? 33 c7 83 3d ?? ?? ?? ?? 27 89 45 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RF_2147781555_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RF!MTB"
        threat_id = "2147781555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 4d ec 8b ?? ?? 03 ?? ?? 89 ?? ?? c7 [0-5] fc 03 cf ff 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RF_2147781555_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RF!MTB"
        threat_id = "2147781555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 c7 05 ?? ?? ?? ?? 2e ce 50 91 89 ?? ?? 8b ?? ?? 01 ?? ?? 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RF_2147781555_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RF!MTB"
        threat_id = "2147781555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 eb c7 05 ?? ?? ?? ?? ee 3d ea f4 03 9d ?? ?? ?? ?? 33 da 83 3d [0-10] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RF_2147781555_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RF!MTB"
        threat_id = "2147781555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 03 45 ?? 83 3d ?? ?? ?? ?? 1b 89 45 ?? c7 05 ?? ?? ?? ?? fc 03 cf ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RF_2147781555_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RF!MTB"
        threat_id = "2147781555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fc 03 cf ff [0-9] 1b 75 3c 00 [0-60] ec [0-9] e0 [0-9] ec [0-9] c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RF_2147781555_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RF!MTB"
        threat_id = "2147781555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 45 e0 89 45 ?? c7 ?? ?? ?? ?? ?? 84 cd 10 fe 8b ?? ?? 33 ?? ?? 89 ?? ?? c7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RF_2147781555_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RF!MTB"
        threat_id = "2147781555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 2e eb ed 8b ?? ?? 8b ?? ?? 8d 1c 38 8b c7 d3 e8 8b ?? ?? c7 ?? ?? ?? ?? ?? 2e ce 50 91 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RF_2147781555_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RF!MTB"
        threat_id = "2147781555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 05 03 55 ?? c7 [0-10] b4 02 d7 cb c7 [0-10] 89 ?? ?? 89 ?? ?? 8b ?? ?? 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RF_2147781555_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RF!MTB"
        threat_id = "2147781555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 4d e0 89 4d ?? c7 05 ?? ?? ?? ?? 82 cd 10 fe 8b ?? ?? 33 ?? ?? 89 ?? ?? 83 ?? ?? ?? ?? ?? 0f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RF_2147781555_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RF!MTB"
        threat_id = "2147781555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 fe 93 8d 6a 8b ?? ?? 33 c3 31 ?? ?? 8b ?? ?? 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 26 04 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RF_2147781555_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RF!MTB"
        threat_id = "2147781555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d1 8b 4d ?? d3 e8 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 45 ?? 33 c2 89 45 ?? 81 fe a3 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RF_2147781555_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RF!MTB"
        threat_id = "2147781555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 89 55 ?? 8b ?? ?? 03 ?? ?? 89 ?? ?? c7 05 ?? ?? ?? ?? 82 cd 10 fe 8b ?? ?? 33 ?? ?? 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RF_2147781555_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RF!MTB"
        threat_id = "2147781555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 45 e0 89 45 ?? c7 05 ?? ?? ?? ?? 82 cd 10 fe 8b 45 ?? 81 05 ?? ?? ?? ?? 7e 32 ef 01 01 ?? ?? ?? ?? ?? 8b ?? ?? 33 0d ?? ?? ?? ?? 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RF_2147781555_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RF!MTB"
        threat_id = "2147781555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d ec 03 4d ?? 89 4d ?? c7 05 ?? ?? ?? ?? 82 cd 10 fe 8b 55 ?? 33 55 ?? 89 55 ?? 81 3d ?? ?? ?? ?? 8d 00 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RF_2147781555_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RF!MTB"
        threat_id = "2147781555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 8d 54 05 ?? 8d 44 24 ?? c7 05 ?? ?? ?? ?? b4 02 d7 cb c7 05 ?? ff ff ff ff 89}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e0 04 89 [0-10] 01 [0-5] 8b [0-5] 8b [0-5] 03 c8 81 3d [0-5] be 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 9c 06 00 00 74 ?? 40 89 45 ?? 3d 81 84 13 01 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 ca 33 c8 [0-10] a3 01 00 00 c7 [0-5] ee 3d ea f4 89 [0-5] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 03 45 ?? 8d 4d [0-5] c7 05 ?? ?? ?? ?? b4 02 d7 cb c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 89 55 ?? 8b ?? ?? 01 ?? ?? c7 [0-5] 64 61 15 fe 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 89 55 ?? 8b ?? ?? 01 ?? ?? c7 [0-5] 64 61 15 fe 8b ?? ?? 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fc 03 cf ff [0-30] 1b 75 3c 00 [0-60] d3 [0-9] 89 [0-30] 89 [0-30] c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fb 61 36 13 01 0f [0-5] eb ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 33 ff 81 ff cb 04 00 00 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 ?? ?? c7 ?? ?? ?? ?? ?? 2e ce 50 91 8b ?? ?? ?? ?? ?? 01 ?? ?? 81 ?? ?? ?? ?? ?? d0 04 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 fe 93 8d 6a 8b ?? ?? 33 cb 33 ?? ?? 8d ?? ?? ?? ?? ?? 89 ?? ?? e8 ?? ?? ?? ?? 89 ?? ?? 25}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 eb c7 05 ?? ?? ?? ?? 2e ce 50 91 89 45 ?? 03 9d ?? ?? ?? ?? 33 d8 81 3d ?? ?? ?? ?? b7 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f0 89 45 ?? 89 75 ?? 8b 45 ?? 29 45 ?? 25 bb 52 c0 5d 8b 55 ?? 8b c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ec 1c 04 00 00 a1 ?? ?? ?? ?? 33 c4 89 84 24 ?? ?? ?? ?? a1 [0-10] 8b 3d ?? ?? ?? ?? a3 ?? ?? ?? ?? 33 f6 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fd 9d 06 00 00 74 ?? 45 81 fd 61 36 13 01 0f [0-5] eb [0-5] a1 [0-5] a3 [0-5] 33 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 fe 93 8d 6a 8b 85 ?? ?? ?? ?? 8d 0c 18 8b 85 ?? ?? ?? ?? 33 c1 31 45 ?? 81 3d ?? ?? ?? ?? a3 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 04 89 ?? ?? 8b ?? ?? 01 ?? ?? 8b ?? ?? 03 ?? ?? 89 ?? ?? c7 ?? ?? ?? ?? ?? e4 fa d6 cb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 89 ?? ?? 8b ?? ?? 01 ?? ?? 8b ?? ?? 03 ?? ?? 89 ?? ?? 81 ?? ?? ?? ?? ?? 96 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 04 89 [0-5] 8b [0-5] 01 [0-5] 8b [0-5] 03 [0-5] 89 [0-5] 81 [0-5] be 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 89 45 ?? 03 ?? ?? 33 d0 89 ?? ?? 8b ?? ?? 29 ?? ?? 25 bb 52 c0 5d 8b ?? ?? 8b c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_18
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c7 05 ?? ?? ?? ?? 2e ce 50 91 e8 ?? ?? ?? ?? 8b ?? ?? d3 ee 89 ?? ?? 03 ?? ?? 33 f0 2b fe 25 bb 52 c0 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_19
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 c7 05 ?? ?? ?? ?? 2e ce 50 91 e8 ?? ?? ?? ?? 8b 4d ?? 8b fe d3 ef 03 7d ?? 33 f8 81 fa 8f 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_20
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 04 89 4d ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 8b 55 ?? 03 d0 81 3d ?? ?? ?? ?? be 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_21
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 89 55 ?? 8b ?? ?? 01 ?? ?? c7 ?? ?? ?? ?? ?? 64 61 15 fe 8b ?? ?? 81 ?? ?? ?? ?? ?? 9c 9e ea 01 01 ?? ?? ?? ?? ?? 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_22
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 45 e0 89 45 ?? c7 ?? ?? ?? ?? ?? 82 cd 10 fe 8b ?? ?? 81 ?? ?? ?? ?? ?? 7e 32 ef 01 01 ?? ?? ?? ?? ?? 8b ?? ?? 33 ?? ?? 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_23
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 55 e0 89 55 ?? c7 ?? ?? ?? ?? ?? 36 06 ea e9 8b ?? ?? 81 ?? ?? ?? ?? ?? ca f9 15 16 01 ?? ?? ?? ?? ?? 8b ?? ?? 33 [0-5] 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_24
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 8b 4d ?? 03 ce 51 03 55 ?? c7 05 ?? ?? ?? ?? 2e ce 50 91 89 55 ?? e8 ?? ?? ?? ?? 89 45 ?? 81 fb e6 09 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_25
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c5 33 44 24 ?? c7 05 [0-10] 89 44 24 ?? 8b 44 24 ?? 01 05 ?? ?? ?? ?? 2b 74 24 ?? c7 05 ?? ?? ?? ?? b4 21 e1 c5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_26
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 86 76 13 01 89 44 24 ?? 0f 8c ?? ?? ?? ?? eb ?? 8b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 7c 24 ?? 8b 1d ?? ?? ?? ?? 8b 2d ?? ?? ?? ?? 33 f6 81 fe 13 4d 00 00 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_27
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e ce 50 91 e8 ?? ?? ?? ?? 8b [0-5] 8b [0-10] d3 [0-5] 03 [0-5] 33 [0-10] 8f 01 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {25 bb 52 c0 5d 8b 45 ?? 03 c3 50 8b c3 c1 e0 04 03 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_28
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 eb c7 05 ?? ?? ?? ?? 2e ce 50 91 89 ?? ?? 8b ?? ?? 01 ?? ?? 83}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 ef c7 05 ?? ?? ?? ?? 2e ce 50 91 89 ?? ?? 8b ?? ?? 01 ?? ?? 83}  //weight: 1, accuracy: Low
        $x_1_3 = {d3 eb 89 45 ?? c7 ?? ?? ?? ?? ?? 2e ce 50 91 89 ?? ?? 8b ?? ?? 01 ?? ?? 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Azorult_RT_2147781645_29
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RT!MTB"
        threat_id = "2147781645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 89 55 ?? 8b ?? ?? 03 ?? ?? 89 ?? ?? ?? ?? e4 ?? ?? f0 89 ?? ?? ?? ?? ec 31 ?? ?? ?? ?? e4 29 ?? ?? 81 [0-6] 17 04 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c3 89 45 ?? c7 [0-10] 8b [0-10] 8d [0-10] e8 ?? ?? ?? ?? 8b ?? ?? 03 ?? ?? 89 ?? ?? c7 ?? ?? ?? ?? ?? fc 03 cf ff 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Azorult_OB_2147781711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.OB!MTB"
        threat_id = "2147781711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 39 3d [0-6] 8b [0-5] 8b [0-5] 8d [0-3] 8b [0-5] 8a [0-3] 8b [0-5] 88 [0-3] 81 3d [0-8] 46 3b [0-9] e8 [0-4] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_ML_2147782666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.ML!MTB"
        threat_id = "2147782666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d e4 33 4d f0 89 4d e4 8b 55 e4 33 55 ec 89 55 e4 8b 45 d0 2b 45 e4 89 45 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_OC_2147783286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.OC!MTB"
        threat_id = "2147783286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 0c 16 81 3d [0-8] 46 3b [0-5] a1 [0-4] 8a [0-6] 8b 15}  //weight: 1, accuracy: Low
        $x_1_2 = {88 0c 16 81 3d [0-8] 46 3b [0-7] e8 [0-4] e8 [0-4] 8b [0-5] 8b [0-7] eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_OD_2147783287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.OD!MTB"
        threat_id = "2147783287"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 53 ff d7 46 3b [0-5] 8b [0-5] 8a [0-6] 8b [0-5] 88 [0-2] 81 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_OE_2147783315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.OE!MTB"
        threat_id = "2147783315"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 0c 16 81 3d [0-8] 46 3b [0-5] a1 [0-4] 8a [0-6] 8b 15}  //weight: 1, accuracy: Low
        $x_1_2 = {88 0c 16 81 3d [0-8] 46 3b [0-7] e8 [0-4] e8 [0-4] 8b [0-5] 8b [0-5] 33 f6 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_OF_2147783388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.OF!MTB"
        threat_id = "2147783388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 39 1d [0-6] 8b [0-5] 8b [0-5] 8a [0-6] 8b [0-5] 88 [0-2] 81 3d [0-8] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f6 39 1d [0-4] e8 [0-4] e8 [0-4] 8b [0-5] 8b [0-5] 33 f6 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_OG_2147783938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.OG!MTB"
        threat_id = "2147783938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 5d 74 89 [0-5] 89 [0-5] 8b [0-5] 29 [0-2] 81 3d [0-8] ba [0-4] 8d [0-5] e8 [0-4] ff [0-5] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_OH_2147783976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.OH!MTB"
        threat_id = "2147783976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 8d [0-2] 89 [0-2] e8 [0-4] 8b [0-5] 8b [0-5] 8d [0-2] e8 [0-4] 81 3d [0-10] 33 [0-2] 89 [0-5] 89 [0-5] 8b [0-5] 29 [0-2] 81 3d [0-8] ba [0-4] 8d [0-5] 29 11 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_OI_2147784052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.OI!MTB"
        threat_id = "2147784052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 7d 74 89 [0-5] 89 [0-5] 8b [0-5] 29 [0-2] 81 3d [0-8] 81 [0-9] ff [0-5] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_SM_2147786253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.SM!MTB"
        threat_id = "2147786253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 45 70 ff 8d a4 fd ff ff ?? ?? ?? ?? ?? ?? 8b 45 6c 89 5f 04 89 07}  //weight: 1, accuracy: Low
        $x_1_2 = {33 45 74 89 35 ?? ?? ?? 00 89 85 a8 fd ff ff 8b 85 a8 fd ff ff 29 45 6c 81 3d ?? ?? ?? 00 b6 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RS_2147788118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RS!MTB"
        threat_id = "2147788118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea c7 05 ?? ?? ?? ?? 2e ce 50 91 89 ?? ?? 8b ?? ?? 01 ?? ?? 83 ?? ?? ?? ?? ?? 67 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 cb 33 4d ?? 8d ?? ?? 89 ?? ?? e8 ?? ?? ?? ?? 89 ?? ?? 25 1b 07 d0 4d 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Azorult_RWA_2147788214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RWA!MTB"
        threat_id = "2147788214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ec 98 09 00 00 83 3d ?? ?? ?? ?? 37 0f [0-5] 33 c0 89 45 ?? 89 45 ?? 89 45 ?? 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RWA_2147788214_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RWA!MTB"
        threat_id = "2147788214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ec 1c 04 00 00 a1 ?? ?? ?? ?? 33 c4 89 84 24 ?? ?? ?? ?? a1 ?? ?? ?? ?? 56 57 8b 3d ?? ?? ?? ?? a3 ?? ?? ?? ?? 33 f6 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {81 fe cc 6b 84 00 75 ?? b8 31 a2 00 00 01 05 ?? ?? ?? ?? 46 81 fe c5 0a 26 01 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_DA_2147789532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.DA!MTB"
        threat_id = "2147789532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c7 45 f4 02 00 00 00 83 45 f4 03 8b 8d 1c fd ff ff 8b c3 c1 e0 04 89 85 30 fd ff ff 8d 85 30 fd ff ff}  //weight: 5, accuracy: High
        $x_5_2 = {8b 4d f8 03 cb 8b 85 2c fd ff ff c1 e8 05 89 45 fc}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_DA_2147789532_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.DA!MTB"
        threat_id = "2147789532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 1c 38 d3 ef c7 05 ?? ?? ?? ?? 2e ce 50 91 89 7d f8 8b 45 ?? 01 45 f8 81 3d ?? ?? ?? ?? eb 03 00 00 75 10 00 c7 05 ?? ?? ?? ?? 40 2e eb ed 8b 45 ?? 8b 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e8 89 45 ec 8b 4d ec 03 4d d4 89 4d ec 8b 55 e4 33 55 f0 89 55 1a 00 c7 05 ?? ?? ?? ?? 84 10 d6 cb c7 05 ?? ?? ?? ?? ff ff ff ff 8b 45 f4 8b 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Azorult_RMA_2147795132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RMA!MTB"
        threat_id = "2147795132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4d ?? c7 ?? ?? ?? ?? ?? 2e ce 50 91 89 ?? ?? 8d ?? ?? e8 ?? ?? ?? ?? 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RMA_2147795132_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RMA!MTB"
        threat_id = "2147795132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 bb 52 c0 5d 8b 55 ?? 8b 7d ?? 8b ca c1 e1 04 03 4d ?? 8b c2 c1 e8 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RMA_2147795132_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RMA!MTB"
        threat_id = "2147795132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 fe 93 8d 6a 8d 04 16 31 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 31 45 ?? 81 3d ?? ?? ?? ?? a3 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RMA_2147795132_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RMA!MTB"
        threat_id = "2147795132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 45 ?? 33 c3 81 3d ?? ?? ?? ?? b7 01 00 00 89 45 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RMA_2147795132_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RMA!MTB"
        threat_id = "2147795132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c3 89 44 24 ?? 8b [0-10] c1 ee 05 03 74 24 ?? 83 3d ?? ?? ?? ?? 1b c7 05 ?? ?? ?? ?? fc 03 cf ff 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RMA_2147795132_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RMA!MTB"
        threat_id = "2147795132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 18 53 8b 1d ?? ?? ?? ?? 56 8b 35 ?? ?? ?? ?? 33 c0 57 8b 3d ?? ?? ?? ?? 89 45 ?? eb ?? 8d 49 ?? 81 3d ?? ?? ?? ?? 3f 12 00 00 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_BB_2147795451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.BB!MTB"
        threat_id = "2147795451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d}  //weight: 10, accuracy: High
        $x_10_2 = {c3 c1 e0 04 89 01 c3 33 44 24 04 c2 04 00 81 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_BD_2147795452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.BD!MTB"
        threat_id = "2147795452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {55 8b ec 51 c7 45 fc 02 00 00 00 8b 45 0c 90 01 45 fc 83 6d fc 02 8b 45 08 8b 08 33 4d fc 8b 55 08 89 0a 8b e5 5d c2 08 00}  //weight: 10, accuracy: High
        $x_10_2 = {8b 4d a8 d3 e8 89 45 ec 8b 4d ec 03 4d d4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_BQ_2147795512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.BQ!MTB"
        threat_id = "2147795512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 4d a8 d3 ea 89 55 ec 8b 45 ec 03 45 d4 89 45 ec 8b 4d e4 33 4d f0 89 4d e4 8b 45 ec 31 45 e4 8b 55 d0 2b 55 e4 89 55 d0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RE_2147806224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RE!MTB"
        threat_id = "2147806224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ec 83 e4 f8 b8 78 41 00 00 e8 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 77 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RWB_2147807881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RWB!MTB"
        threat_id = "2147807881"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ff f9 a8 d5 6a 0f 8c ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 33 c9 89 4d ?? 81 f9 fa 03 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_GFS_2147809831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.GFS!MTB"
        threat_id = "2147809831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reiudxamcsyuasdx.exe" ascii //weight: 1
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "CryptDecrypt" ascii //weight: 1
        $x_1_4 = "omefnsxsdcway" ascii //weight: 1
        $x_1_5 = "navefkdeecsfw" ascii //weight: 1
        $x_1_6 = "mksamfesasf" ascii //weight: 1
        $x_1_7 = "amvsivmeofjcs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_DG_2147809903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.DG!MTB"
        threat_id = "2147809903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "MLTOL6zaAYLs9M9ZP6KbV7ug9IDaPI8e" ascii //weight: 3
        $x_3_2 = "RegisterAutomation" ascii //weight: 3
        $x_3_3 = "CurrentVersion\\Run" ascii //weight: 3
        $x_3_4 = "Treda.doc" ascii //weight: 3
        $x_3_5 = "\\Macromedia\\" ascii //weight: 3
        $x_3_6 = "LockResource" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RTA_2147809928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RTA!MTB"
        threat_id = "2147809928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 fe 93 8d 6a 8b 85 ?? ?? ?? ?? 8d 0c 17 33 c1 31 45 ?? 81 3d ?? ?? ?? ?? a3 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RTA_2147809928_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RTA!MTB"
        threat_id = "2147809928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 03 44 24 ?? 83 3d ?? ?? ?? ?? 1b 89 44 24 ?? c7 05 ?? ?? ?? ?? fc 03 cf ff 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RTA_2147809928_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RTA!MTB"
        threat_id = "2147809928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 [0-4] 31 [0-4] 8b [0-10] 03 [0-4] 33 [0-5] 83 [0-5] 27 c7 [0-5] 2e ce 50 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RMB_2147812768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RMB!MTB"
        threat_id = "2147812768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 05 50 c7 05 ?? ?? ?? ?? b4 21 e1 c5 c7 05 ?? ?? ?? ?? ff ff ff ff 03 d5 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_M_2147813138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.M!MTB"
        threat_id = "2147813138"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 85 ec fd ff ff 83 c0 01 89 85 ec fd ff ff 83 bd ec fd ff ff 14 7d 4b 8b 8d ec fd ff ff 8b 14 8d ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 8b 85 ec fd ff ff 89 14 85 ?? ?? ?? ?? 83 bd ec fd ff ff 13 7d 20 8b 8d ec fd ff ff 8b 14 8d 28 21 41 00 81 ea ?? ?? ?? ?? 8b 85 ec fd ff ff 89 14 85 ?? ?? ?? ?? eb 9d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_MA_2147813148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.MA!MTB"
        threat_id = "2147813148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 8b 15 b4 38 45 00 52 8b 45 f4 50 8b 0d 4c 2b 45 00 ff d1 8b 55 f4 52 a1 50 2b 45 00 ff d0 b9 01 00 00 00 6b d1 00 03 15 b4 38 45 00 89 15 bc 39 45 00 a1 bc 39 45 00 0f b7 08 81 f9 4d 5a 00 00 74 24}  //weight: 1, accuracy: High
        $x_1_2 = {0f af c3 fe c8 0f ba e0 10 0f ad d8 3c 50 0f ba e0 a8 8a c6 3a c6 86 e0 48 3a c6 0f ac d8 d0}  //weight: 1, accuracy: High
        $x_1_3 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_N_2147813646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.N!MTB"
        threat_id = "2147813646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c7 04 24 00 00 00 00 83 04 24 04 8b 0c 24 8b 44 24 0c d3 e0 8b 4c 24 08 89 01 59 c2 08 00}  //weight: 5, accuracy: High
        $x_5_2 = {8b 44 24 0c 8b 4c 24 04 c1 e8 05 89 01 89 44 24 0c 8b 44 24 0c 03 44 24 08 89 44 24 0c 8b 44 24 0c 89 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_EM_2147814047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.EM!MTB"
        threat_id = "2147814047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 75 f4 8b 4d f0 8b c6 d3 e0 8b 4d fc 8b d6 c1 ea 05 03 45 d0 03 55 d4 03 ce 33 c1 33 c2 2b f8 89 55 f8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_EM_2147814047_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.EM!MTB"
        threat_id = "2147814047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {c1 e2 04 89 54 24 10 8b 44 24 24 01 44 24 10 8b 7c 24 18 8b ce c1 e9 05 03 cd 03 fe}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_EM_2147814047_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.EM!MTB"
        threat_id = "2147814047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {31 7c 24 0c 8b 44 24 10 31 44 24 0c 8b 44 24 0c 29 44 24 18 8b 44 24 24 29 44 24 14 ff 4c 24 1c}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_EM_2147814047_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.EM!MTB"
        threat_id = "2147814047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {0f b7 c0 f3 0f 58 c8 0f 57 c0 f3 0f 2a c0 f3 0f 58 c8 0f 57 c0}  //weight: 3, accuracy: High
        $x_2_2 = {8b f9 2b f8 89 7c 24 40 8b 7c 24 58 8b 44 24 5c 8a 54 24 67 88 10}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RFA_2147814163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RFA!MTB"
        threat_id = "2147814163"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 33 45 ?? 81 3d ?? ?? ?? ?? a3 01 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_CA_2147814332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.CA!MTB"
        threat_id = "2147814332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 c0 81 c4 14 11 00 00 c3 b8 40 1c 00 00}  //weight: 5, accuracy: High
        $x_5_2 = {8d 44 24 20 50 6a 00 ff d6 6a 00 8d 8c 24 54 0c 00 00 51 ff d7 8d 54 24 28 52 ff d3 8d 44 24 24 50 c7 44 24 28 00 00 00 00 ff d5 6a 00 8d 8c 24 54 14 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_CA_2147814332_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.CA!MTB"
        threat_id = "2147814332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "gujujoxefiyopuxemuga" ascii //weight: 3
        $x_3_2 = "norihisecodote" ascii //weight: 3
        $x_3_3 = "ZUKAMAJIMERO" ascii //weight: 3
        $x_3_4 = "GetComputerNameExW" ascii //weight: 3
        $x_3_5 = "WriteProfileSectionA" ascii //weight: 3
        $x_3_6 = "GetNumaHighestNodeNumber" ascii //weight: 3
        $x_3_7 = "EnumResourceNamesA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_CB_2147814333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.CB!MTB"
        threat_id = "2147814333"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 44 24 14 3d 9d 06 00 00 74 12 40 3d c6 7c 13 01 89 44 24 14 0f 8c c2 fe ff ff eb 0c}  //weight: 5, accuracy: High
        $x_5_2 = {33 c9 33 c0 8d 54 24 20 52 66 89 44 24 14 66 89 4c 24 16 8b 44 24 14}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_CB_2147814333_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.CB!MTB"
        threat_id = "2147814333"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 78 8b 4d 7c 31 08 83 c5 70 c9 c2 08 00 8b 44 24 04 8b 4c 24 08 01 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_CB_2147814333_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.CB!MTB"
        threat_id = "2147814333"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 59 85 c0 75 17 8b 45 fc 8b 4d e8 0f b7 04 41 8b 4d e4 8b 55 08 03 14 81 8b c2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_CB_2147814333_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.CB!MTB"
        threat_id = "2147814333"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8b 44 24 04 8b 4c 24 08 29 08 c2 08 00 55 8b ec 51 8b 4d 08 8b 45 0c 83 65 fc 00 89 01 8b 45 0c 33 45 fc 89 45 fc 8b 45 fc 89 01}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_CC_2147814334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.CC!MTB"
        threat_id = "2147814334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 c9 33 c0 8d 54 24 24 52 66 89 44 24 20 66 89 4c 24 22 8b 44 24 20 50 51 51 51 ff d6 6a 00 ff d7}  //weight: 5, accuracy: High
        $x_5_2 = {33 ed 33 db 81 fb 13 4d 00 00 7d 0f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_MC_2147814653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.MC!MTB"
        threat_id = "2147814653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c0 33 d2 8d 4c 24 18 51 66 89 54 24 18 66 89 44 24 1a 8b 54 24 18 52 50}  //weight: 5, accuracy: High
        $x_5_2 = {50 6a 00 ff d6 6a 00 8d 8c 24 ?? ?? ?? ?? 51 ff d7 8d 54 24 ?? 52 ff d3 6a 00 ff d5 6a 00 8d 84 24}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_CD_2147815303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.CD!MTB"
        threat_id = "2147815303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8d 44 24 20 50 6a 00 ff d6 6a 00 8d 8c 24 54 18 00 00 51 ff d7 8d 54 24 28 52 ff d3 8d 44 24 24 50 c7 44 24 28 00 00 00 00 ff d5 6a 00 8d 8c 24 54 10 00 00 51}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_CD_2147815303_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.CD!MTB"
        threat_id = "2147815303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 8c 01 3b 2d 0b 00 8b 15 [0-4] 88 0c 02 8b 15 [0-4] 40 3b c2 72 df}  //weight: 2, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_CM_2147816182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.CM!MTB"
        threat_id = "2147816182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c7 45 f8 02 00 00 00 83 45 f8 03 8b 8d 24 fd ff ff 8b c3 c1 e0 04 89 85 2c fd ff ff 8d 85 2c fd ff ff}  //weight: 5, accuracy: High
        $x_5_2 = {81 00 47 86 c8 61 c3 81 00 e1 34 ef c6 c3 01 08 c3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RK_2147816281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RK!MTB"
        threat_id = "2147816281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 70 00 00 00 03 45 ?? 0f b7 40 ?? 89 45 ?? 8b 45 ?? 89 45 ?? 8b 4d ?? 33 4d ?? 89 4d ?? 8b 4d ?? 03 4d ?? 89 4d ?? e9 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? b9 0e 00 00 00 8d 55 ?? 83 ec 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_AF_2147816943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.AF!MTB"
        threat_id = "2147816943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 51 c7 45 fc 02 00 00 00 8b 45 0c 01 45 fc 83 6d fc 02 8b 45 08 8b 4d fc 31 08 c9}  //weight: 5, accuracy: High
        $x_5_2 = {55 8b ec 51 83 65 fc 00 83 45 fc 04 8b 4d fc 8b 45 0c d3 e0 8b 4d 08 89 01 c9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_AM_2147817296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.AM!MTB"
        threat_id = "2147817296"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b cf c1 e1 04 03 8d 74 ff ff ff 3d a9 0f 00 00 75 0a}  //weight: 3, accuracy: High
        $x_3_2 = {8b 45 88 c1 e8 05 89 45 fc 8b 45 80 01 45 fc}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_XT_2147823763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.XT!MTB"
        threat_id = "2147823763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 69 88 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 50 72 6f 74 c7 05 ?? ?? ?? ?? 65 63 74 00 c7 05 ?? ?? ?? ?? 74 75 61 6c ff 15 ?? ?? ?? ?? a3 3d 00 50 a3 ?? ?? ?? ?? 66 c7 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_EH_2147828527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.EH!MTB"
        threat_id = "2147828527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {c7 45 fc 02 00 00 00 8b 45 0c 90 01 45 fc 83 6d fc 02 8b 45 08 8b 4d fc 31 08}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_EH_2147828527_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.EH!MTB"
        threat_id = "2147828527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2b f0 8b d6 c1 e2 04 89 44 24 14 89 54 24 10 8b 44 24 2c 01 44 24 10 8b c6 c1 e8 05 03 c5 03 fe}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_EH_2147828527_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.EH!MTB"
        threat_id = "2147828527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 51 c7 45 fc 02 00 00 00 8b 45 0c 01 45 fc 83 6d fc 02 8b 45 08 8b 4d 0c 31 08 c9 c2 08 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_EH_2147828527_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.EH!MTB"
        threat_id = "2147828527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2b f0 8b ce c1 e1 04 89 44 24 14 89 4c 24 10 8b 44 24 28 01 44 24 10 8b d6 c1 ea 05 03 d5 8d 04 37 31 44 24 10}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_EH_2147828527_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.EH!MTB"
        threat_id = "2147828527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 c2 08 00 55 8b ec 51 83 65 fc 00 8b 45 10 90 01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_EH_2147828527_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.EH!MTB"
        threat_id = "2147828527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 51 c7 45 fc 02 00 00 00 8b 45 0c 01 45 fc 83 6d fc 02 8b 45 08 8b 4d 0c 31 08 c9 c2 08 00 55 8b ec 8b 45 08 8b 4d 0c 01 08 5d c2 08 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_EN_2147829908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.EN!MTB"
        threat_id = "2147829908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {81 00 e1 34 ef c6 c3 29 08 c3 01 08 c3 01 08 c3}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_EN_2147829908_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.EN!MTB"
        threat_id = "2147829908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 04 24 89 c3 03 5c 24 08 89 5c 24 14 8b 54 24 10 8b 44 24 14 8a 1a 8a 38 30 fb 88 1a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RPY_2147831132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RPY!MTB"
        threat_id = "2147831132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 c1 e0 04 03 c2 8b d1 03 4c 24 08 c1 ea 05 03 54 24 04 33 c2 33 c1 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RPY_2147831132_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RPY!MTB"
        threat_id = "2147831132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 8b 30 8b 40 04 89 45 f8 8b 45 0c 8b 08 89 4d e0 8b 48 04 89 4d e8 8b 48 08 8b 40 0c 57}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 08 89 78 04 5f 89 30 5e 5b c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RPY_2147831132_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RPY!MTB"
        threat_id = "2147831132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 7c 24 10 89 6c 24 18 8b 44 24 24 01 44 24 18 8b 44 24 38 90 01 44 24 18 8b 44 24 18 89 44 24 20 8b 4c 24 1c 8b 44 24 20 8b d6 d3 ea 8b 4c 24 10 50 51 03 d3 89 54 24 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RPC_2147831191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RPC!MTB"
        threat_id = "2147831191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 4d fc 8b 55 f0 8b 02 2b c1 8b 4d f0 89 01 8b 55 f4 8b 45 f0 8b 08 89 0a 8b 55 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RPC_2147831191_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RPC!MTB"
        threat_id = "2147831191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d1 e0 0f be 4c 05 f4 c1 f9 02 03 d1 8b 45 ec 03 45 f8 88 10 8b 4d f8 83 c1 01 89 4d f8 ba 01 00 00 00 6b c2 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RPK_2147831761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RPK!MTB"
        threat_id = "2147831761"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f6 d1 fe c1 32 c8 02 c8 f6 d1 02 c8 80 f1 c1 02 c8 fe c9 80 f1 d7 fe c9 88 88}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RPD_2147832125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RPD!MTB"
        threat_id = "2147832125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b c0 4c 6b f0 62 8b 45 0c 8b 4d f4 0f be 14 08 31 f2 88 14 08 8b 45 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_EB_2147833070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.EB!MTB"
        threat_id = "2147833070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 51 83 65 fc 00 8b 45 0c 89 45 fc 8b 45 08 31 45 fc 8b 45 fc 89 01 c9 c2 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_EB_2147833070_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.EB!MTB"
        threat_id = "2147833070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 51 c7 45 fc 04 00 00 00 8b 45 0c 83 6d fc 04 90 01 45 fc 8b 45 08 8b 4d fc 31 08 c9 c2 08 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_EB_2147833070_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.EB!MTB"
        threat_id = "2147833070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4d ec 8b c7 d3 e0 8b 4d f4 8b d7 d3 ea 03 45 d4 89 45 fc 8b 45 e8 03 55 d0 03 c7 89 45 f0 8b 45 f0 31 45 fc 31 55 fc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_EB_2147833070_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.EB!MTB"
        threat_id = "2147833070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {8b 4d e4 8b d6 d3 e2 89 5d e8 03 55 c8 89 55 f4 8b 45 f0 01 45 e8 8b 45 dc 90 01 45 e8 8b 45 e8 89 45 e0 8b 4d ec 8b c6 d3 e8 89 45 f8}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_ER_2147834883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.ER!MTB"
        threat_id = "2147834883"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "csgo.exe" ascii //weight: 1
        $x_1_2 = "client.dll" ascii //weight: 1
        $x_1_3 = "cheat-menu.pdb" ascii //weight: 1
        $x_1_4 = "gRU.o0XGH" ascii //weight: 1
        $x_1_5 = "ZI_kS&ai" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RPG_2147835439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RPG!MTB"
        threat_id = "2147835439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 45 dc 89 45 f8 33 c7 31 45 fc 8b 45 f0 89 45 e4 8b 45 fc 29 45 e4 8b 45 e4 89 45 f0 8b 45 c4 29 45 f4 ff 4d d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RPE_2147836422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RPE!MTB"
        threat_id = "2147836422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e1 04 03 cb 33 4d 08 33 4d 0c 2b f1 89 4d 08 89 75 e8 8b 45 e8 03 45 f4 89 45 0c}  //weight: 1, accuracy: High
        $x_1_2 = {89 45 08 8b 45 e4 01 45 08 ff 75 08 8b c6 c1 e0 04 03 45 e0 33 45 0c 89 45 fc 8d 45 fc 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_EC_2147837764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.EC!MTB"
        threat_id = "2147837764"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 51 8b 4d 08 8b 45 0c 83 65 fc 00 89 01 8b 45 0c 33 45 fc 89 45 fc 8b 45 fc 89 01 c9 c2 0c 00 8b 44 24 04 8b 4c 24 08 31 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RPF_2147838255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RPF!MTB"
        threat_id = "2147838255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 fa 5f 01 da 81 ea ?? ?? ?? ?? 53 bb 00 00 00 00 01 d3 01 0b 5b 5a 5b 81 ec 04 00 00 00 89 3c 24 68 04 00 00 00 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RPZ_2147842548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RPZ!MTB"
        threat_id = "2147842548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 45 f0 8b 45 f0 89 45 ec 8b 4d f4 8b c3 d3 e8 03 45 d0 89 45 f8 8b 45 ec 31 45 fc 8b 45 fc 33 45 f8 29 45 e4 89 45 fc 8d 45 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_GFT_2147842838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.GFT!MTB"
        threat_id = "2147842838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 c1 e8 ?? 03 c5 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 8d 44 24 ?? 89 4c 24 ?? e8 ?? ?? ?? ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 83 ef}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RPX_2147850589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RPX!MTB"
        threat_id = "2147850589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 6c 24 14 8d 0c 17 89 4c 24 24 8b 4c 24 1c d3 ea 89 54 24 18 8b 44 24 34 01 44 24 18 8b 44 24 24 31 44 24 14 8b 4c 24 14 33 4c 24 18 8d 44 24 28 89 4c 24 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_GMD_2147853507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.GMD!MTB"
        threat_id = "2147853507"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Electrum\\wallets" wide //weight: 1
        $x_1_2 = "system32\\timeout.exe 3 & del" wide //weight: 1
        $x_1_3 = "PasswordsList.txt" ascii //weight: 1
        $x_1_4 = "scr.jpg" ascii //weight: 1
        $x_1_5 = "ip.txt" ascii //weight: 1
        $x_1_6 = "System.txt" ascii //weight: 1
        $x_1_7 = "Coins\\Ethereum" wide //weight: 1
        $x_1_8 = "Ethereum\\keystore" wide //weight: 1
        $x_1_9 = "Coins\\Exodus" wide //weight: 1
        $x_1_10 = "Telegram Desktop\\tdata\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_B_2147891365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.B!MTB"
        threat_id = "2147891365"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 d0 23 ca 0f b7 95 ?? ?? ?? ?? 33 d1 66 89}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_GAC_2147898776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.GAC!MTB"
        threat_id = "2147898776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 14 1f 89 55 ?? 8b d3 d3 ea c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 ?? 8b 45 ?? 31 45 ?? 33 55 ?? 89 55 ?? 8b 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_DE_2147900949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.DE!MTB"
        threat_id = "2147900949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 33 d2 f7 75 f0 8a 04 32 30 04 19 41 3b cf 72 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_CH_2147901015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.CH!MTB"
        threat_id = "2147901015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 51 5a 36 41 0d 0a 6d 6e 48 68 53 0d 0a 6c 66 56 54 47 32 0d [0-4] 4d 0d 0a 4d 47 53 43 0d 0a 6f 5a 65}  //weight: 1, accuracy: Low
        $x_1_2 = {41 69 0d 0a 51 72 57 36 0d 0a 77 65 63 77 50 0d 0a 50 4f 64 66 55 0d 0a 47 6f 64 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_RC_2147901066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.RC!MTB"
        threat_id = "2147901066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 e0 8b 45 f0 33 45 e0 89 45 f0 8b 4d e8 03 4d f4 8a 55 f0 88 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_C_2147906984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.C!MTB"
        threat_id = "2147906984"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 d2 f7 75 ?? 8b 45 ?? 0f b6 0c 10 8b 55 ?? 03 55 ?? 0f b6 02 33 c1 8b 4d ?? 03 4d ?? 88 01}  //weight: 2, accuracy: Low
        $x_2_2 = {0f b7 45 ec 6b c8 ?? 8b 55 e8 8b 44 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_EZ_2147923902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.EZ!MTB"
        threat_id = "2147923902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b cf c1 e9 ?? 89 4d ?? 8b 45 ?? 01 45 ?? 8b 55 ?? 8b 45 ?? c1 e7 04 03 7d ?? 03 c2 33 f8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_GNT_2147924213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.GNT!MTB"
        threat_id = "2147924213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 ca 8b 45 ?? c1 e8 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 33 f1 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_SZSB_2147924652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.SZSB!MTB"
        threat_id = "2147924652"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {03 c8 8b 45 f0 c1 e8 05 89 45 f8 8b 55 dc 01 55 f8 33 f1 81 3d a4 88 45 00 e6 09 00 00 c7 05 9c 88 45 00 ee 3d ea f4 75 0c}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_BAF_2147934835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.BAF!MTB"
        threat_id = "2147934835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 07 83 ef fc f7 d8 8d 40 d7 83 c0 fe 40 29 d0 29 d2 09 c2 6a 00 8f 03 01 03 83 eb fc 83 ee fc}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_BAE_2147935603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.BAE!MTB"
        threat_id = "2147935603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {29 c0 2b 07 f7 d8 8d 7f 04 f7 d0 f8 83 d0 df 8d 40 ff 29 d0 89 c2 89 06 83 ee fc f8 83 d1 fc}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_BAG_2147935610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.BAG!MTB"
        threat_id = "2147935610"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {58 23 01 f8 83 d1 04 f7 d0 8d 40 da f8 83 d8 01 29 d8 89 c3 89 07 83 c7 04 f8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_BAO_2147935615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.BAO!MTB"
        threat_id = "2147935615"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {03 1a 83 ea fc 83 c3 d4 c1 cb 08 29 fb 8d 5b ff 29 ff 09 df c1 c7 0a c1 cf 02 53 8f 06}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_CL_2147941760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.CL!MTB"
        threat_id = "2147941760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Vobixosidiyove0Yitobodi nahazuwuriguhi sugidov mos moyurizuwehe" wide //weight: 1
        $x_1_2 = "Hakal berizes cak dovaz3Rojeyopirey wazetam yowayah sasetakitoxap kojunocag" wide //weight: 1
        $x_1_3 = "Wuhirufu lipekuf yobozep" wide //weight: 1
        $x_1_4 = "Tuxipemakapawu)Zinazesod komixuwitok sepabopoducojuy ciw0Sawe cepebuwahunar movapoluculax posugodiziparuk" wide //weight: 1
        $x_1_5 = "Xilafewic zawumiyalele" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Azorult_SEZC_2147942172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Azorult.SEZC!MTB"
        threat_id = "2147942172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "xovahuges.exe" ascii //weight: 2
        $x_1_2 = "MyFunc124@@4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

