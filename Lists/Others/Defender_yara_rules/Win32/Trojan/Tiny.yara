rule Trojan_Win32_Tiny_FBE_2147712301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tiny.FBE!bit"
        threat_id = "2147712301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 1d 00 10 40 00 89 9d f8 07 00 00 a1 a0 30 40 00 89 45 30 a1 9c 30 40 00 89 45 38}  //weight: 1, accuracy: High
        $x_1_2 = {68 20 4e 00 00 ff 15 a8 30 40 00 6a 04 68 00 30 00 00 68 00 14 00 00 6a 00 ff 15 ac 30 40 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 ff 55 30 90 89 45 48 90 e8 0f 00 00 00 49 73 57 6f 77 36 34 50 72 6f 63 65 73 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tiny_FBF_2147714340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tiny.FBF!bit"
        threat_id = "2147714340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 00 01 da 83 c2 0c 31 0a 3b 85 ?? ?? ?? ?? 73 08 83 c0 04 83 c3 04 eb e6}  //weight: 1, accuracy: Low
        $x_1_2 = {80 7c 03 ff c3 74 02 eb ?? 8b 45 00 83 c0 0c ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tiny_PA_2147742751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tiny.PA!MTB"
        threat_id = "2147742751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "http://77.73.69.179:9/mk/p%u.php?a=%u" ascii //weight: 2
        $x_2_2 = "http://77.73.70.247:9/mk/p%u.php?a=%u" ascii //weight: 2
        $x_2_3 = {43 3a 5c 54 45 4d 50 5c 6d 69 61 [0-5] 2e 74 6d 70}  //weight: 2, accuracy: Low
        $x_1_4 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 63 6d 64 2e 65 78 65 20 2f 63 20 64 65 6c 20 22 43 3a 5c 54 45 4d 50 5c 6d 69 61 [0-5] 2e 74 6d 70}  //weight: 1, accuracy: Low
        $x_1_5 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 6e 65 74 73 68 2e 65 78 65 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d 20 22 [0-32] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tiny_O_2147795122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tiny.O!MTB"
        threat_id = "2147795122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BreakWeaponData_relative" ascii //weight: 1
        $x_1_2 = "crmplogger_universal" ascii //weight: 1
        $x_1_3 = "radmir_parser215" ascii //weight: 1
        $x_1_4 = "steal\\Release\\gtasteal.pdb" ascii //weight: 1
        $x_1_5 = "Agent SBU" ascii //weight: 1
        $x_1_6 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_7 = "InternetCreateUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tiny_AD_2147796745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tiny.AD!MTB"
        threat_id = "2147796745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 08 0f be 08 88 4d ff 8b 45 08 89 c1 40 89 45 08 8b 45 f8 0f be 10 88 11 8b 45 f8 0f be 4d ff 88 08}  //weight: 10, accuracy: High
        $x_10_2 = {88 45 99 b8 20 00 00 00 88 45 9a b8 64 00 00 00 88 45 9b b8 6d 00 00 00 88 45 9c b8 63 00 00 00 88 45 9d}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tiny_EC_2147842231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tiny.EC!MTB"
        threat_id = "2147842231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "185.215.113.84/peinstall.php" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileW" ascii //weight: 1
        $x_1_3 = "CreateProcessW" ascii //weight: 1
        $x_1_4 = "GetStartupInfoA" ascii //weight: 1
        $x_1_5 = "twizt.ru/newtpp.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tiny_EH_2147843680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tiny.EH!MTB"
        threat_id = "2147843680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "185.215.113.66" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileW" ascii //weight: 1
        $x_1_3 = "CreateProcessW" ascii //weight: 1
        $x_1_4 = "CreateFileW" ascii //weight: 1
        $x_1_5 = "ShellExecuteW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tiny_PAAT_2147851595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tiny.PAAT!MTB"
        threat_id = "2147851595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 45 fa 8b c8 89 1d 4c 86 40 00 c1 e8 04 83 e1 03 83 e0 01 89 0d 54 86 40 00 8a 0d 60 83 40 00 a3 50 86 40 00 b8 61 83 40 00 3a cb a3 24 83 40 00 74 0c}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\kasoft\\" ascii //weight: 1
        $x_1_3 = "n\\boot.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tiny_EB_2147890016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tiny.EB!MTB"
        threat_id = "2147890016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ltiapmyzmjxrvrts.info" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = "%%temp%%\\%s.exe" ascii //weight: 1
        $x_1_4 = "http://%s.%s/v4/%s.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tiny_NT_2147900571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tiny.NT!MTB"
        threat_id = "2147900571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d8 b8 08 00 00 00 e8 bf d9 ff ff 8b 15 ?? ?? ?? ?? 89 10 89 58 04 a3 10 30 05 00 5b c3}  //weight: 5, accuracy: Low
        $x_1_2 = "Ein Systemfehler ist aufgetrete" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tiny_ATY_2147908635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tiny.ATY!MTB"
        threat_id = "2147908635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 6a 06 6a 01 6a 02 ff 15 10 31 01 10 a3 10 b4 01 10 68 00 a0 01 10 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tiny_EN_2147939573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tiny.EN!MTB"
        threat_id = "2147939573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {c1 e2 02 8b 5d 00 8b 5b 08 8b 1b 89 d9 8b 1b 8b 45 08 c1 e0 02 01 c3 8b 1b 85 db 81 fb 01}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tiny_PPG_2147949922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tiny.PPG!MTB"
        threat_id = "2147949922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "You Are Fucked, Your information is now ours, Your files are now encrypted, Now start huffing the copium" ascii //weight: 4
        $x_1_2 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 [0-112] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f [0-112] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tiny_AB_2147951434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tiny.AB!MTB"
        threat_id = "2147951434"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 ec 1c 02 00 00 a1 e0 85 03 10 33 c4 89 84 24 18 02 00 00 8b 84 24 20 02 00 00 8b 40 14 b9 00 01 00 00 56 89 4c 24 0c 89 4c 24 10 85 c0 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tiny_A_2147959259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tiny.A!AMTB"
        threat_id = "2147959259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "http://185.215.113.66/" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

