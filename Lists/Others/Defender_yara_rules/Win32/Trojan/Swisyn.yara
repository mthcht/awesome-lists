rule Trojan_Win32_Swisyn_E_2147632136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Swisyn.E"
        threat_id = "2147632136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 6d 61 67 65 6e 74 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 61 73 73 65 73 2e 78 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 67 74 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_4 = {2a 69 6e 74 65 72 6e 65 74 20 65 78 70 6c 6f 72 65 72 2a 00}  //weight: 1, accuracy: High
        $x_1_5 = {6b 65 79 6c 6f 67 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {70 61 73 6c 69 73 74 2e 74 78 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Swisyn_T_2147641497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Swisyn.T"
        threat_id = "2147641497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 cf 8b fa 03 d2 83 e1 1f 03 d2 c1 ef 1b 33 cf 33 ca 8b d0}  //weight: 1, accuracy: High
        $x_1_2 = {68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 cf 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 15 3a 01 00 68 90 5d 3a 00 68 c9 75 65 00 e8 ?? ?? 00 00 83 c4 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Swisyn_J_2147647902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Swisyn.J"
        threat_id = "2147647902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {33 d2 f2 ae 89 54 24 19}  //weight: 10, accuracy: High
        $x_10_2 = {c6 44 24 24 00 c6 44 24 10 00 f3 a5 8b c8}  //weight: 10, accuracy: High
        $x_10_3 = {33 c0 8b fe 68 04 01 00 00 f3 ab 56 ff 15}  //weight: 10, accuracy: High
        $x_10_4 = {85 c0 74 27 6a 14 ff 15}  //weight: 10, accuracy: High
        $x_1_5 = {41 75 5f 6a 69 68 61 6f 00}  //weight: 1, accuracy: High
        $x_1_6 = {41 75 5f 69 6e 69 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Swisyn_M_2147691818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Swisyn.M!dha"
        threat_id = "2147691818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 08 8a 08 2a ca 32 ca 88 08 40 4e 75 f4}  //weight: 1, accuracy: High
        $x_1_2 = {81 e5 00 f0 ff ff 81 fd 00 30 00 00 75 ?? 8b 6c 24 18 25 ff 0f 00 00 03 c7 01 28 8b 41 04}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 0c 4a a9 00 00 00 04 8d 14 4e 8b 14 95 d0 40 00 10}  //weight: 1, accuracy: High
        $x_1_4 = "%APPDATA%\\Microsoft\\wuauclt\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Swisyn_U_2147709858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Swisyn.U!bit"
        threat_id = "2147709858"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sc stop WinDefend" wide //weight: 1
        $x_1_2 = "sc delete WinDefend" wide //weight: 1
        $x_1_3 = "sc stop MpsSvc /f" wide //weight: 1
        $x_1_4 = "sc delete MpsSvc /f" wide //weight: 1
        $x_1_5 = "DisableCMD /t REG_DWORD /d 1 /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Swisyn_ADA_2147783530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Swisyn.ADA!MTB"
        threat_id = "2147783530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Win.uExWatch" ascii //weight: 3
        $x_3_2 = "mExInternet" ascii //weight: 3
        $x_3_3 = "URLDownloadToFileA" ascii //weight: 3
        $x_3_4 = "DeleteUrlCacheEntryA" ascii //weight: 3
        $x_3_5 = "tmrSec" ascii //weight: 3
        $x_3_6 = "tmrPri" ascii //weight: 3
        $x_3_7 = "GdipGetImageEncoders" ascii //weight: 3
        $x_3_8 = "ClientToScreen" ascii //weight: 3
        $x_3_9 = "ShellIE_WindowRegistered" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Swisyn_MBHW_2147888485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Swisyn.MBHW!MTB"
        threat_id = "2147888485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 3e 40 00 01 f8 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 02 00 01 00 e9 00 00 00 74 3b 40 00 14 3c 40 00 18 29 40 00 78 00 00 00 83 00 00 00 8c}  //weight: 1, accuracy: High
        $x_1_2 = {41 00 2a 00 5c 00 41 00 46 00 3a 00 5c 00 52 00 46 00 44 00 5c 00 78 00 4e 00 65 00 77 00 43 00 6f 00 64 00 65 00 5c 00 78 00 4e 00 65 00 77 00 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Swisyn_GMH_2147890055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Swisyn.GMH!MTB"
        threat_id = "2147890055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 b7 88 61 b8 ?? ?? ?? ?? 03 c5 81 c0 93 00 00 00 b9 34 06 00 00 ba ?? ?? ?? ?? 30 10 40 49}  //weight: 10, accuracy: Low
        $x_1_2 = "TJprojMain.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Swisyn_GNF_2147896386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Swisyn.GNF!MTB"
        threat_id = "2147896386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rfGsEA1#" ascii //weight: 1
        $x_1_2 = "@Mv$ew/1" ascii //weight: 1
        $x_1_3 = "wa?k4g2a" ascii //weight: 1
        $x_1_4 = "qfxrnSkBNkj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Swisyn_MBXR_2147919374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Swisyn.MBXR!MTB"
        threat_id = "2147919374"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 35 40 00 01 f8 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 64 32 40 00 68 31 40 00 fc 2b 40 00 78 00 00 00 83 00 00 00 87 00 00 00 88}  //weight: 1, accuracy: High
        $x_1_2 = "KLprojMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Swisyn_ARAZ_2147929141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Swisyn.ARAZ!MTB"
        threat_id = "2147929141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 44 24 10 8d 54 24 14 6a 04 52 6a 04 6a 00 68 cc c1 b0 00 50 89 7c 24 2c ff d6 8b 54 24 10 8d 4c 24 14 6a 04 51 6a 04 6a 00 68 c0 c1 b0 00 52 c7 44 24 2c 03 00 00 00 ff d6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Swisyn_ASW_2147933246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Swisyn.ASW!MTB"
        threat_id = "2147933246"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {56 56 68 20 f7 e1 00 56 56 50 8b 44 24 2c 6a 01 6a 03 68 10 01 00 00 68 ff 01 0f 00 50 50 57 ff 15 ?? ?? ?? ?? 8b 1d 04 60 e1 00 8b f0 85 f6 74 25 8b 4c 24 1c 8b 54 24 18 51 52 56}  //weight: 2, accuracy: Low
        $x_1_2 = {8d 53 41 8d 44 24 14 52 68 5c b1 e1 00 50 e8 ?? ?? ?? ?? 83 c4 0c 8d 4c 24 14 51 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

