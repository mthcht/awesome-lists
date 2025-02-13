rule Trojan_Win32_Zegost_CJ_2147727947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zegost.CJ!bit"
        threat_id = "2147727947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 10 b9 fe 00 00 00 25 ff 00 00 00 89 65 f0 99 f7 f9 c7 45 ec 00 00 00 00 80 c2 58 88 55 13}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 08 8a 4d 13 8a 10 32 d1 02 d1 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zegost_CK_2147728203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zegost.CK!bit"
        threat_id = "2147728203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b c6 44 24 ?? 52 c6 44 24 ?? 4e c6 44 24 ?? 4c c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e}  //weight: 1, accuracy: Low
        $x_1_2 = {5c c6 44 24 ?? 75 c6 44 24 ?? 70 c6 44 24 ?? 64 c6 44 24 ?? 61 c6 44 24 ?? 74 c6 44 24 ?? 61 c6 44 24 ?? 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 14 01 80 c2 ?? 80 f2 ?? 88 14 01 83 c1 01 3b ce 7c ed}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zegost_CL_2147730257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zegost.CL!bit"
        threat_id = "2147730257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 45 10 99 b9 fe 00 00 00 f7 f9 89 65 f0 c7 45 e8 00 00 00 00 80 c2 ?? 88 55 ef}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 8a 10 8a 4d ef 32 d1 02 d1 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zegost_CN_2147730304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zegost.CN!bit"
        threat_id = "2147730304"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 54 24 08 8d 42 0c 8b 4a e0 33 c8}  //weight: 1, accuracy: High
        $x_1_2 = {c6 85 ec fe ff ff 4b c6 85 ed fe ff ff 6f c6 85 ee fe ff ff 74 c6 85 ef fe ff ff 68 c6 85 f0 fe ff ff 65 c6 85 f1 fe ff ff 72 c6 85 f2 fe ff ff 35 c6 85 f3 fe ff ff 39 c6 85 f4 fe ff ff 39}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zegost_CO_2147733873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zegost.CO!bit"
        threat_id = "2147733873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 0a 75 c6 44 24 0b 72 c6 44 24 0c 6c c6 44 24 0e 67 c6 44 24 0f 2e c6 44 24 10 64 c6 44 24 11 61 c6 44 24 12 74 c6 44 24 13 00}  //weight: 1, accuracy: High
        $x_1_2 = {8a 10 32 d1 02 d1 88 10 40 4e 75 f4}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 c5 49 c6 45 c6 44 c6 45 c7 3a c6 45 c9 30 c6 45 ca 31 c6 45 cb 34 c6 45 cc 2d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zegost_RT_2147779783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zegost.RT!MTB"
        threat_id = "2147779783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 49 00 a1 ?? ?? ?? ?? 69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 30 0c 37 83 fb 19 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zegost_RM_2147780847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zegost.RM!MTB"
        threat_id = "2147780847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 f9 8b 74 24 ?? 80 c2 58 85 f6 76 ?? 8b 44 24 ?? 8a 08 32 ca 02 ca 88 08 40 4e 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zegost_PEF_2147798650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zegost.PEF!MTB"
        threat_id = "2147798650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 10 8b c8 c1 e9 18 88 0c 3e 8b c8 c1 e9 10 88 4c 3e 01 8b c8 c1 e9 08 88 4c 3e 02 88 44 3e 03 83 c6 04 ff 44 24 18 8b 44 24 18 3b 44 24 14 72 9e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zegost_RB_2147838544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zegost.RB!MTB"
        threat_id = "2147838544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 6a 40 68 00 30 00 00 68 5c dd 04 00 8b f1 6a 00 ff 15 ?? ?? ?? ?? 85 c0 75 02 5e c3 57 6a 00 6a 00 50 b9 57 37 01 00 81 c6 74 dd 04 00 8b f8 50 6a 00 6a 00 f3 a5 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zegost_RC_2147846584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zegost.RC!MTB"
        threat_id = "2147846584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bduninstall.exe" ascii //weight: 1
        $x_1_2 = "bctrl.exe" ascii //weight: 1
        $x_1_3 = "undoabledisk.dll" ascii //weight: 1
        $x_1_4 = "drivers\\undovol.sys" ascii //weight: 1
        $x_1_5 = "h:\\$udjour$.$$$" ascii //weight: 1
        $x_1_6 = "bitnet2005\\install\\Win32\\Release\\deinstall.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zegost_DAL_2147850609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zegost.DAL!MTB"
        threat_id = "2147850609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b1 a4 ab 38 b5 32 0d c9 b8 ad e5 ab 69 89 6a ad fc f8 b2 d7 cc 93 35 5a 3d da 96 2d e8 a2 3e 49 07 45 ad 79}  //weight: 2, accuracy: High
        $x_2_2 = {12 28 38 9b 1f 71 be 5c 4a 92 e6 cf a7 35 b1 66 7d ca 13 66 55 a7 50 6f 42 94 3a b4 ab d5 ad 11 b3 8a c5 5a d5 ec 51 ad 51 71}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zegost_EN_2147851362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zegost.EN!MTB"
        threat_id = "2147851362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /f /im ipaip2.exe" ascii //weight: 1
        $x_1_2 = "/c rmdir /s /q" ascii //weight: 1
        $x_1_3 = "InternetCheckConnectionA" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_5 = "[Down]" ascii //weight: 1
        $x_1_6 = "[Right]" ascii //weight: 1
        $x_1_7 = "[Left]" ascii //weight: 1
        $x_1_8 = "Sea.Working.Mou" ascii //weight: 1
        $x_1_9 = "Outpost Firewall" ascii //weight: 1
        $x_1_10 = "TrojanHunter.exe" ascii //weight: 1
        $x_1_11 = "KSWebShield.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zegost_RDA_2147892996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zegost.RDA!MTB"
        threat_id = "2147892996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {88 4d f3 0f be 55 ff 0f be 45 f3 33 d0 88 55 ff 8b 4d d0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zegost_ARA_2147920778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zegost.ARA!MTB"
        threat_id = "2147920778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 04 0a 34 5b 88 01 41 4d 75 f5}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

