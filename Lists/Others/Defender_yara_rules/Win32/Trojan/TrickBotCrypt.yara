rule Trojan_Win32_TrickBotCrypt_DSA_2147764209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DSA!MTB"
        threat_id = "2147764209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 37 0f b6 c0 03 c2 33 d2 f7 f1 8b 44 24 20 8b da 03 d8 ff 15 ?? ?? ?? ?? 8a 0c 33 8a 44 24 28 8b 54 24 1c 02 c8 8b 44 24 14 32 0c 02 88 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_MS_2147774360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.MS!MTB"
        threat_id = "2147774360"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 c0 8a fc 8a e6 d3 cb ff 4d fc 75 [0-24] 31 [0-3] 8b [0-2] aa 49 75}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 c0 8a fc 8a e6 d3 cb ff 4d fc 75 [0-24] 33 [0-5] 8b [0-2] aa 49 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_MU_2147778119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.MU!MTB"
        threat_id = "2147778119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 06 46 [0-4] 51 50 c7 [0-6] 59 bb [0-4] 89 [0-2] 33 [0-7] 31 ?? 8b [0-2] c7 [0-6] d3 ?? 8a ?? 8a ?? d3 ?? ff [0-2] 75 ?? 59 53 8f [0-2] ff [0-2] 58 aa 49 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_MV_2147778328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.MV!MTB"
        threat_id = "2147778328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 06 46 85 c0 74 48 56 83 [0-3] 09 [0-2] 55 c7 [0-6] 59 bb [0-4] 50 83 e0 00 09 f0 83 e2 00 09 c2 58 c7 45 [0-5] d3 c0 8a fc 8a e6 d3 cb ff 4d fc 75 f3 8f 45 f4 8b 4d f4 89 75 f4 31 f6 09 de 89 f0 8b 75 f4 aa 49 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_MW_2147778673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.MW!MTB"
        threat_id = "2147778673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MALSERVICE" ascii //weight: 1
        $x_1_2 = "Recent File Li" ascii //weight: 1
        $x_1_3 = "\\ShellNew" ascii //weight: 1
        $x_1_4 = "\\shell\\printto\\" ascii //weight: 1
        $x_1_5 = "commdlg_FileNameOK" ascii //weight: 1
        $x_1_6 = "commdlg_LBSelChangedNotify" ascii //weight: 1
        $x_1_7 = "AfxFrameOrView42s" ascii //weight: 1
        $x_1_8 = "CryptImportKey" ascii //weight: 1
        $x_1_9 = "SizeofResource" ascii //weight: 1
        $x_1_10 = "FindResourceA" ascii //weight: 1
        $x_1_11 = "LoadResource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_MX_2147778674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.MX!MTB"
        threat_id = "2147778674"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "splt\\init_v" ascii //weight: 1
        $x_1_2 = "SSTestSetts" ascii //weight: 1
        $x_1_3 = "SSTest.Document" ascii //weight: 1
        $x_1_4 = "CSSTestDoc" ascii //weight: 1
        $x_1_5 = "Recent File Li" ascii //weight: 1
        $x_1_6 = "CryptImportKey" ascii //weight: 1
        $x_1_7 = "\\ShellNew" ascii //weight: 1
        $x_1_8 = "\\shell\\printto\\" ascii //weight: 1
        $x_1_9 = "commdlg_FileNameOK" ascii //weight: 1
        $x_1_10 = "commdlg_LBSelChangedNotify" ascii //weight: 1
        $x_1_11 = "AfxFrameOrView42s" ascii //weight: 1
        $x_1_12 = "LdrAccessResource" ascii //weight: 1
        $x_1_13 = "CStatusBar" ascii //weight: 1
        $x_1_14 = "msctls_statusbar32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_MY_2147780223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.MY!MTB"
        threat_id = "2147780223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 d0 8b ce 3b ?? 73 ?? eb ?? 8d ?? ?? 8a ?? 2a ?? 32 ?? 32 ?? 88 ?? 03 ?? ?? 3b ?? 72 ?? 8b ?? ?? 46 ff ?? ?? 8a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_MZ_2147781345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.MZ!MTB"
        threat_id = "2147781345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 14 8b [0-3] 8b [0-3] 8a [0-2] 8a [0-2] 32 ?? 8b [0-3] 88 [0-2] 40 3b ?? 89 [0-3] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_DA_2147783311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DA!MTB"
        threat_id = "2147783311"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 0e 0f b6 0c 0f 03 c1 99 b9 ?? ?? ?? ?? f7 f9 88 54 24 ?? ff d3 ff d3 ff d3 0f b6 54 24 ?? 8b 0d ?? ?? ?? ?? 8b 44 24 ?? 8a 14 0a 30 14 28}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 04 33 f6 d0 8b ce 3b f7 73 ?? 8a d9 2a da 32 19 32 d8 88 19 03 4d ?? 3b cf 72 ?? 8b 5d ?? 46 ff 4d ?? 75}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 04 33 f6 d0 8b ce 3b 75 ?? 73 ?? 8a d9 2a da 32 19 32 d8 88 19 03 cf 3b 4d ?? 72 ?? 8b 5d ?? 46 ff 4d ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_DB_2147784152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DB!MTB"
        threat_id = "2147784152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 3b 81 e1 ff 00 00 00 03 c1 f7 35 ?? ?? ?? ?? 89 54 24}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d6 8b 54 24 ?? 8b 44 24 ?? 8b 4c 24 ?? 8a 14 3a 30 14 08 8b 4c 24 ?? 40 3b c1 89 44 24 ?? 0f 82 66 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_DC_2147784156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DC!MTB"
        threat_id = "2147784156"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 3b 80 f1 20 8b c7 3b fe 73 ?? 8d 64 24 00 8a d8 2a da 80 e3 20 32 18 32 d9 88 18 03 45 ?? 3b c6 72 ?? 8b 5d ?? 47 ff 4d 08 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_DD_2147784159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DD!MTB"
        threat_id = "2147784159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "??0CDllLoader@@QAE@PBD_N@Z" ascii //weight: 1
        $x_1_2 = "?terminate@@YAXXZ" ascii //weight: 1
        $x_1_3 = "!!5rnqqzz!OW_B?" ascii //weight: 1
        $x_1_4 = "GuiLib" ascii //weight: 1
        $x_1_5 = "Locked" ascii //weight: 1
        $x_1_6 = "keybd_event" ascii //weight: 1
        $x_1_7 = "SetCapture" ascii //weight: 1
        $x_1_8 = "GetKeyState" ascii //weight: 1
        $x_1_9 = "Zoom Out" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_DF_2147786209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DF!MTB"
        threat_id = "2147786209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 55 fc 33 d2 f7 35 ?? ?? ?? ?? 8b 45 0c 8a 1d ?? ?? ?? ?? 89 55 f4 8b 55 f8 8d 0c 02 8a c3 f6 eb 8b 5d f4 8a 1c 33 2a d8 30 19 42 89 55 f8 3b 55 10 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_DH_2147786216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DH!MTB"
        threat_id = "2147786216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 03 4d e4 0f b6 11 03 c2 33 d2 f7 35 ?? ?? ?? ?? 89 55 e8 8b 45 f0 8b 08 8b 55 f8 8b 02 8b 55 08 0f b6 04 02 03 05 ?? ?? ?? ?? 8b 55 0c 0f b6 0c 0a 33 c8 8b 55 f0 8b 02 8b 55 0c 88 0c 02 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_NA_2147786269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.NA!MTB"
        threat_id = "2147786269"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d ec 3b [0-4] 8b [0-2] 0f [0-2] 0f [0-3] 33 ?? 8b [0-2] 2b [0-2] 0f [0-2] 83 [0-2] 33 ?? 8b [0-2] 88 ?? 8b [0-2] 03 [0-2] 89 [0-2] eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_DL_2147786526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DL!MTB"
        threat_id = "2147786526"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 02 0f b6 4d ?? 33 c1 8b 55 ?? 2b 55 ?? 0f b6 ca 81 e1 80 00 00 00 33 c1 8b 55 ?? 88 02 8b 45 ?? 03 45 ?? 89 45 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_DM_2147786527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DM!MTB"
        threat_id = "2147786527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 1c 32 2a d8 0f b6 05 ?? ?? ?? ?? b2 03 f6 ea 8b 55 ?? 02 d8 02 1d ?? ?? ?? ?? 8b 45 ?? 30 1c 10 40 89 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_DG_2147786652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DG!MTB"
        threat_id = "2147786652"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 0e 0f b6 d2 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 45 0c 0f b6 14 0a 02 15 ?? ?? ?? ?? 30 54 03 ff 3b 5d 10 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_DP_2147786656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DP!MTB"
        threat_id = "2147786656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 11 0f b6 45 ?? 33 d0 8b 4d ?? 2b 4d ?? 0f b6 c1 25 80 00 00 00 33 d0 8b 4d ?? 88 11 8b 55 ?? 03 55 ?? 89 55 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_DN_2147786758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DN!MTB"
        threat_id = "2147786758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {8b 55 08 33 db 8a 1c 0a 03 c3 33 d2 f7 35 ?? ?? ?? ?? 89 55 f4 8b 45 fc 8b 08 8b 55 e4 8b 02 8b 55 08 33 db 8a 1c 02}  //weight: 6, accuracy: Low
        $x_10_2 = {2b da 8b 45 0c 8a 0c 08 32 cb 8b 55 fc 8b 02 8b 55 0c 88 0c 02 e9}  //weight: 10, accuracy: High
        $x_10_3 = "HttpAnalyzer.EXE" ascii //weight: 10
        $x_1_4 = "DisableThreadLibraryCalls" ascii //weight: 1
        $x_1_5 = "StartW" ascii //weight: 1
        $x_1_6 = "AVtype_info" ascii //weight: 1
        $x_1_7 = "GetTempFileNameA" ascii //weight: 1
        $x_1_8 = "kanjimenu" ascii //weight: 1
        $x_1_9 = "hangeulmenu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_TrickBotCrypt_DO_2147786759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DO!MTB"
        threat_id = "2147786759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 08 8b c2 33 d2 8a 14 0e 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8a c3 b3 0f f6 2d ?? ?? ?? ?? f6 eb 8a d8 a0 ?? ?? ?? ?? 02 d8 c0 e3 04 8a 04 0a 02 d8 a0 ?? ?? ?? ?? 2a d8 8b 44 24 18 8a 14 28 32 d3 88 14 28 8b 44 24 1c 45 3b e8 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_DQ_2147786761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DQ!MTB"
        threat_id = "2147786761"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b da 03 1d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 2b d9 03 1d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 2b da 8b 4d ?? 8a 14 01 32 d3 8b 45 ?? 8b 08 8b 45 ?? 88 14 08 e9}  //weight: 1, accuracy: Low
        $x_1_2 = "6O?jM2M5wkWiN)SDgAUyDr^+m&!Z*XttC^Mf)u4($w6l8n7BHw>S+g?>nh5gjICoU8IwQcH+5AlJmoU!o2n" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_DR_2147786762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DR!MTB"
        threat_id = "2147786762"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 32 33 d2 8a 14 37 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8a c3 b3 1f f6 2d ?? ?? ?? ?? f6 eb 8a 14 32 2a d0 a0 ?? ?? ?? ?? f6 eb 02 d0 a0 ?? ?? ?? ?? 2a d0 8b 44 24 ?? 8a 1c 01 32 da 88 1c 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_DS_2147787026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DS!MTB"
        threat_id = "2147787026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 02 0f b6 4d ?? 33 c1 8b 55 ?? 2b 55 ?? 0f b6 ca 83 e1 20 33 c1 8b 55 ?? 88 02 8b 45 ?? 03 45 ?? 89 45 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_DT_2147787027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DT!MTB"
        threat_id = "2147787027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 08 8b 55 ?? 8b 02 8b 55 ?? 8b 75 ?? 8a 0c 0a 32 0c 06 8b 55 ?? 8b 02 8b 55 ?? 88 0c 02 e9 03 00 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_DU_2147787028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DU!MTB"
        threat_id = "2147787028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OJJeht?eyRS2lm<9NW18xlhaiS06MkJnM3M6IO_z" ascii //weight: 1
        $x_1_2 = "Fuck Windows Defender" ascii //weight: 1
        $x_1_3 = "StartW" ascii //weight: 1
        $x_1_4 = "sc.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_DV_2147787176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DV!MTB"
        threat_id = "2147787176"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 02 80 f1 80 3b c6 73 ?? 8b ff 8a d0 2a d3 80 e2 80 32 10 32 d1 88 10 03 c7 3b c6 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_DW_2147787177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DW!MTB"
        threat_id = "2147787177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 0e 03 c2 33 d2 f7 35 ?? ?? ?? ?? a0 ?? ?? ?? ?? 8a 14 0a 02 d0 8b 44 24 ?? 8a 1c 28 32 da 88 1c 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_DX_2147787178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DX!MTB"
        threat_id = "2147787178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f8 8a c1 f6 eb b1 1f f6 e9 8a 0c 32 b2 1f 2a c8 a0 ?? ?? ?? ?? f6 ea 02 c8 2a 0d ?? ?? ?? ?? 30 0f 06 00 8b 45 ?? 8b 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_DY_2147787179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DY!MTB"
        threat_id = "2147787179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 32 2a d0 a0 ?? ?? ?? ?? f6 e9 8b 4c 24 1c 02 d0 a0 ?? ?? ?? ?? 2a d0 8b 44 24 10 8a 1c 08 32 da 88 1c 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_DZ_2147787180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DZ!MTB"
        threat_id = "2147787180"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%%S1z00foJ67HZzqI&PD1TZbG+yWEQzFgbhVf1zuA2O5#c$+neFP3F&8N?N61NFX+t7MCtN7G#7)?qvgY>wY_dvK@7" ascii //weight: 1
        $x_1_2 = "blah blah blah..." ascii //weight: 1
        $x_1_3 = "StartW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EA_2147787223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EA!MTB"
        threat_id = "2147787223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 08 0f b6 55 ?? 33 ca 8b 45 ?? 2b 45 ?? 0f b6 d0 81 e2 ff 00 00 00 33 ca 8b 45 ?? 88 08 8b 4d ?? 03 4d ?? 89 4d ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EA_2147787223_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EA!MTB"
        threat_id = "2147787223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 04 0e 03 c2 33 d2 f7 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b d8 0f af d8 4b 0f af d8 a1 ?? ?? ?? ?? 03 d3 2b d0 8b 44 24 10 8a 18 8a 14 0a 32 da 88 18}  //weight: 5, accuracy: Low
        $x_5_2 = "8oFbo#HUhz!N^zVN#zfeZg_sMnX?P&7E6%iA#MT&o66it$t_7JQibYfRet7HiP?_*V07vMWb" ascii //weight: 5
        $x_5_3 = "QfRCMv3EHYY<W6%aPUYGUjt*6G#&P&8FabWGeC@Oj&#yI&HpklBI1JyP#ETv_WVRW%BSZG)v&cQ?nysz7JH>!FxCz*ifLON!y1gO7n?Yj070)B" ascii //weight: 5
        $x_5_4 = "NT(Zp#^#@#6I^Akt>JlV&>PYwe40jaZ%nMXN@S*O!jlOJDm7M(vd?UO%x?BmHLmx&((?QdhZ(%ZRw^2gdJ>e5D(O" ascii //weight: 5
        $x_5_5 = "Tjy6o#lWmgu5!I0>4lwys)O^Lq+)o^krUXB8N+5d_(UCdNCjpdUqSiB*$l3$ERnL14xfRj*6!?#x2Hx" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EB_2147787224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EB!MTB"
        threat_id = "2147787224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 4d e8 3b 4d f4 73 ?? 8b 55 e8 0f b6 02 0f b6 4d e7 33 c1 8b 55 e8 2b 55 08 0f b6 ca 81 e1 e0 00 00 00 33 c1 8b 55 e8 88 02 8b 45 e8 03 45 fc 89 45 e8 eb cb}  //weight: 5, accuracy: Low
        $x_5_2 = "<dZ4OH3W>M!hY(_4^Dv977bvV9E8U>&F9^y@imr<)&g+H)9TnJwDf_*3iD6F1g&^*MLpO19HNSpA2Q_?e>^p!oe9dv*Elv9P7?p@" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EB_2147787224_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EB!MTB"
        threat_id = "2147787224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 d0 03 c1 0f b6 1c 10 02 5d ?? 8b 45 ?? 02 1d ?? ?? ?? ?? 8b 55 ?? 30 1c 10 40 89 45 ?? 3b 45 ?? 72}  //weight: 5, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "AVtype_info" ascii //weight: 1
        $x_1_4 = "SemiTransparentDialogWithStandardCtrls.pdb" ascii //weight: 1
        $x_1_5 = "MFC-Examples-main\\MFC-Examples-main" ascii //weight: 1
        $x_1_6 = "NoEntireNetwork" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_TrickBotCrypt_EC_2147787225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EC!MTB"
        threat_id = "2147787225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 eb 8a 0c 31 2a c8 a0 ?? ?? ?? ?? f6 eb 8a 1d ?? ?? ?? ?? 02 c8 8a 45 00 2a cb 32 c1 42 88 45 00 0b 00 a0 ?? ?? ?? ?? f6 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EC_2147787225_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EC!MTB"
        threat_id = "2147787225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 04 0e 89 54 24 10 0f b6 14 0f 03 c2 33 d2 f7 35 ?? ?? ?? ?? b8 02 00 00 00 2b 05 ?? ?? ?? ?? 45 0f af c3 0f af c3 48 03 15 ?? ?? ?? ?? 0f af c3 03 c2 0f b6 14 08 8b 44 24 10 30 10}  //weight: 5, accuracy: Low
        $x_5_2 = {2b d0 2b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 03 d0 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 03 45 08 8b 75 0c 8a 0c 0e 32 0c 10 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 45 ec 2b c2 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 55 0c 88 0c 02 e9}  //weight: 5, accuracy: Low
        $x_5_3 = ">B*X!UfZYE9IceaH7cdx<h_h^1DD3Qtusy?ddO8z$RpA2o%8(ff>#keUM_Fs3Uz^dbeC$q+nXpksxEMWguwUz+jnv" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_ED_2147787364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.ED!MTB"
        threat_id = "2147787364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 14 03 d0 a0 ?? ?? ?? ?? f6 eb 2a c8 8a c1 b1 1f f6 e9 8b 4c 24 ?? 02 04 31 2a 05 ?? ?? ?? ?? 30 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_ED_2147787364_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.ED!MTB"
        threat_id = "2147787364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 14 0f 89 44 24 10 0f b6 04 0e 03 c2 33 d2 f7 35 ?? ?? ?? ?? b8 02 00 00 00 2b 05 ?? ?? ?? ?? 45 0f af c3 0f af c3 48 03 15 ?? ?? ?? ?? 0f af c3 03 c2 8a 14 08 8b 44 24 10 30 10}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EE_2147787508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EE!MTB"
        threat_id = "2147787508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 03 45 f8 0f b6 08 89 4d f4 8b 55 08 03 55 f8 0f b6 02 2b 45 fc 89 45 fc 79 ?? 8b 4d fc 81 c1 00 01 00 00 89 4d fc 8b 55 08 03 55 f8 8a 45 fc 88 02 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EE_2147787508_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EE!MTB"
        threat_id = "2147787508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0a 03 c1 33 d2 f7 35 ?? ?? ?? ?? 89 55 f8 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 45 ec 2b c2}  //weight: 1, accuracy: Low
        $x_1_2 = {2b c2 2b 05 ?? ?? ?? ?? 8b 55 0c 8b 75 08 8a 0c 0a 32 0c 06}  //weight: 1, accuracy: Low
        $x_1_3 = {03 c6 03 d0 03 15 ?? ?? ?? ?? 8b 45 0c 88 0c 10 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EF_2147787509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EF!MTB"
        threat_id = "2147787509"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 02 80 f1 80 3b c6 73 21 8d 9b ?? ?? ?? ?? 8a d0 2a d3 80 e2 80 32 10 32 d1 88 10 03 c7 3b c6 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EF_2147787509_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EF!MTB"
        threat_id = "2147787509"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 32 34 e0 8b ce 3b f7 73 [0-6] 8a d1 2a d3 80 e2 e0 32 11 32 d0 88 11 03 4d f4 3b cf 72 ?? 8b 55 f8 46 ff 4d fc 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EG_2147787534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EG!MTB"
        threat_id = "2147787534"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 02 8b 4d ?? 8b 11 8b 4d ?? 0f b6 14 11 03 15 ?? ?? ?? ?? 8b 4d ?? 0f b6 04 01 33 c2 8b 4d ?? 8b 11 8b 4d ?? 88 04 11}  //weight: 1, accuracy: Low
        $x_1_2 = "M4cx1(BmX>PgSK8>$?9%jK@RU%0YY%I_hqgQHWg<$@k($)iM63@Xw+1zxrJ+k)75!wyXDD4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EG_2147787534_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EG!MTB"
        threat_id = "2147787534"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 0a 8b 54 24 ?? 81 e2 ?? ?? ?? ?? 03 c2 33 d2 f7 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b d8 0f af d8 a1 ?? ?? ?? ?? 2b d3 2b d7 8b 3d ?? ?? ?? ?? 2b d7 03 d0 8b 44 24 ?? 8a 14 0a 8a 18 32 da 8b 54 24 ?? 88 18}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 14 3b 03 c2 33 d2 f7 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 6c 24 ?? 0f af c6 8d 2c 49 2b e8 a1 ?? ?? ?? ?? 0f af e9 0f af e9 03 d5 8d 0c 76 8d 04 82 2b c1 8a 0c 38 8b 44 24 ?? 30 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EH_2147787618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EH!MTB"
        threat_id = "2147787618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 0f b6 0c 08 8b 45 0c 0f b6 14 10 33 d1 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 03 4d f4 03 0d ?? ?? ?? ?? 03 c8 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 8b 45 0c 88 14 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EH_2147787618_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EH!MTB"
        threat_id = "2147787618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f8 8a c1 f6 eb b1 1f f6 e9 8a 0c 32 b2 1f 2a c8 a0 ?? ?? ?? ?? f6 ea 02 c8 2a 0d ?? ?? ?? ?? 30 0f 06 00 8b 45 ?? 8b 7d}  //weight: 1, accuracy: Low
        $x_1_2 = "Ol2A#2>f5v5L8lF&DQR&?8KKOxr5J0+3M?x3JuE1+V!877>_h$>f4i_0w8Y41h>c8mDbDqLDqpMf4R4i8H*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EJ_2147787780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EJ!MTB"
        threat_id = "2147787780"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 0e 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 18 8b 5c 24 1c 2b d0 a1 ?? ?? ?? ?? 2b d3 8b 5c 24 20 2b d0 a1 ?? ?? ?? ?? 03 d3 03 d0 8b 44 24 10 8a 1c 28 8a 14 0a 32 da 88 1c 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EJ_2147787780_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EJ!MTB"
        threat_id = "2147787780"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 e4 8b 12 8b 75 08 33 db 8a 1c 16 03 1d ?? ?? ?? ?? 8a 04 08 32 c3 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 15}  //weight: 1, accuracy: Low
        $x_1_2 = "GUUrl573!9y%jp04)K+3sgSmt@Z8?_VX+5%371e+Axupv<!j<$^XDh%aJNJq?*?m0$S" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EI_2147787834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EI!MTB"
        threat_id = "2147787834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 14 38 8b 44 24 ?? 03 c3 89 44 24 ?? 0f b6 d2 8b c6 2b c1 0f b6 04 38 03 c2 33 d2 bb ?? ?? ?? ?? f7 f3 8b 44 24 ?? 2b 15 ?? ?? ?? ?? 03 54 24 30 03 d5 03 54 24 ?? 8a 14 3a 30 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EI_2147787834_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EI!MTB"
        threat_id = "2147787834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 08 03 55 f4 0f b6 02 89 45 e0 8b 4d 08 03 4d f4 0f b6 11 2b 55 f8 89 55 f8 79 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 08 8b 45 f8 05 00 01 00 00 89 45 f8 8b 4d 08 03 4d f4 8a 55 f8 88 11 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EK_2147787835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EK!MTB"
        threat_id = "2147787835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 55 ff 83 ea 69 88 55 ff 6a 12 e8 ?? ?? ?? ?? 83 c4 04 0f b6 45 ff 0f b6 4d fe 0b c8 88 4d fe 68 0a 01 00 00 e8 ?? ?? ?? ?? 83 c4 04 0f b6 55 fd 0f b6 45 fe 33 c2 88 45 fe 68 12 01 00 00 e8 ?? ?? ?? ?? 83 c4 04 8a 4d fd 80 c1 01 88 4d fd 6a 4a e8 ?? ?? ?? ?? 83 c4 04 8b 55 f4 8a 45 fe 88 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EK_2147787835_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EK!MTB"
        threat_id = "2147787835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 03 ca a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 03 45 0c 8b 55 e4 8b 12 8b 75 08 33 db 8a 1c 16 03 1d ?? ?? ?? ?? 8a 04 08 32 c3}  //weight: 1, accuracy: Low
        $x_1_2 = "mgIL%^Q9%a!vhF4563_X##%o^mmzBkl3rAqr9F(^G5*)FDgJJubd<+sK<3oflE&ZCCspAXDHP?bH3eSGP77&4ukcf#6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EL_2147788052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EL!MTB"
        threat_id = "2147788052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 0e 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 1c 83 c0 fe 0f af 05 ?? ?? ?? ?? 2b d5 8b e9 03 ea 8a 14 28 8a 03 32 c2 8b 54 24 24 88 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EL_2147788052_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EL!MTB"
        threat_id = "2147788052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 95 5c ff ff ff 0f b6 82 00 10 00 00 89 45 ?? 8b 4d ?? 03 8d 5c ff ff ff 0f b6 91 00 10 00 00 2b 55 ?? 89 55 ?? 79 03 00 8b 55}  //weight: 1, accuracy: Low
        $x_1_2 = {05 00 01 00 00 89 45 ?? 8b 4d ?? 03 8d 5c ff ff ff 8a 55 ?? 88 91 00 10 00 00 e9 03 00 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EM_2147788224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EM!MTB"
        threat_id = "2147788224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 29 33 d2 8a 14 0e 03 c2 33 d2 f7 35 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 8a 04 0a 8a 17 32 d0 8b 44 24 20 43 88 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EM_2147788224_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EM!MTB"
        threat_id = "2147788224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 1c 2b c3 8a 1d ?? ?? ?? ?? 83 c0 02 0f af 05 ?? ?? ?? ?? 03 c5 03 c2 8b 54 24 ?? 8a 14 0a 02 d3 8a 18 32 da 45 88 18}  //weight: 1, accuracy: Low
        $x_1_2 = "WA>hT>4Eh+gOZQWL(j%Bp1I1?l+o%Z@#TZriiyk*r5s2rhHvs3RJsur1yfQdji>3x4o5E)YU461Y(wZ#%pE$yMOYVf+G>AxArekeVXiEv4vLyAd0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EN_2147788274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EN!MTB"
        threat_id = "2147788274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 03 c1 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 03 55 0c 8b 4d e4 8b 09 8b 75 08 33 db 8a 1c 0e 03 1d ?? ?? ?? ?? 8a 14 02 32 d3}  //weight: 1, accuracy: Low
        $x_1_2 = "9rc7+5_#Pokx20C$5P8xdvAjsebb+M8+9cMaTgYZMTWo<qq+nm^hCd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EO_2147788275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EO!MTB"
        threat_id = "2147788275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 0e 03 df 8a 04 0b 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8d 45 ff 0f af 05 ?? ?? ?? ?? 03 ea 03 c5 8b 6c 24 1c 8a 14 08 8b 44 24 10 8a 1c 28 32 da 8b 54 24 20 88 1c 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EO_2147788275_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EO!MTB"
        threat_id = "2147788275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d3 2b 15 ?? ?? ?? ?? 8a 1d ?? ?? ?? ?? 83 c2 02 0f af d0 8b 44 24 1c 03 d5 03 c2 8b 54 24 10 8a 14 0a 02 d3 30 10}  //weight: 1, accuracy: Low
        $x_1_2 = "dncSjB#z6Kk0tZDN*Q!(Lg6rDj!ylZn4_^L$xPq9%EHsojo<HoGblLyGoevOgcrQ%GsANE!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EP_2147788438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EP!MTB"
        threat_id = "2147788438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 4c 24 24 89 8c 24 94 00 00 00 83 f5 4d 89 6c 24 28 89 ac 24 98 00 00 00 43 89 5c 24 2c 3b 9c 24 80 00 00 00 0f 8c 23}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EP_2147788438_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EP!MTB"
        threat_id = "2147788438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c3 0f af c7 8d 04 58 2b 05 ?? ?? ?? ?? 03 45 f8 03 c2 8b 55 f4 0f b6 14 32 89 45 f0 8b 45 fc 0f b6 04 30 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 45 f0 41 0f af cf 2b d1 03 d3 8a 0c 32 30 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EP_2147788438_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EP!MTB"
        threat_id = "2147788438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d0 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 03 d1 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 03 45 0c 8b 4d e4 8b 09 8b 75 08 33 db 8a 1c 0e 03 1d ?? ?? ?? ?? 8a 14 10 32 d3}  //weight: 1, accuracy: Low
        $x_1_2 = ")jQX?0Km#kO0raG$@c$&APVD<ROOSr1hj$CCD@l2#fY<>e5?CNaD^003wntczMGclFHx!B#kMi+i" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EQ_2147788439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EQ!MTB"
        threat_id = "2147788439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 33 c9 45 33 c0 ba 04 10 00 00 48 8b 49 40 ff 15 ?? ?? ?? ?? 44 3b f8 0f 8d ?? ?? ?? ?? 3d 01 00 00 8a 06 52 46 30 07 5a 4a 47}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EQ_2147788439_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EQ!MTB"
        threat_id = "2147788439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 ce 89 54 24 ?? 03 c1 8a 0c 3a 8a 15 ?? ?? ?? ?? 8a 18 02 ca 32 d9 8b 4c 24 ?? 88 18 8b 44 24 ?? 40 3b c1 89 44 24 ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = "!5%mnI<DLYRkRIi0hynzj5bXds3^&@!b19gon^Pc#+wOvk8ORglV?kZ>3zhV(^a8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_ER_2147788440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.ER!MTB"
        threat_id = "2147788440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d8 0f af 1d ?? ?? ?? ?? 03 de 8d 04 0b 8a 0d ?? ?? ?? ?? 89 54 24 ?? 8a 14 3a 8a 18 02 d1 8b 4c 24 ?? 32 da 88 18 8b 44 24 ?? 40 3b c1 89 44 24 ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = "N8VYTvDHFLxz50gyjZq^b<gyU^_&Sf(3^GtQth_QBcX676$+o)(s?qZLQ5EoBq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_ES_2147788485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.ES!MTB"
        threat_id = "2147788485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 e4 0f b6 02 0f b6 4d eb 33 c1 8b 55 e4 2b 55 08 0f b6 ca 81 e1 e0 00 00 00 33 c1 8b 55 e4 88 02 8b 45 e4 03 45 f4 89 45 e4 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_ES_2147788485_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.ES!MTB"
        threat_id = "2147788485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f0 8b 45 ?? 03 de 0f af d9 03 5d f0 89 55 ?? 8a 0c 3a 02 0d ?? ?? ?? ?? 03 c3 30 08 ff 45 f0 8b 45 f0 3b 45 ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = "ZLuwss!$5GQ8y8fE+G?tSRZK69YL^dJ9StTWSG)V9oxM1dVFCoXkv<i(@agy+g70IUlt_H^zbui@Cl+@^fC#rk(<ASw&_lVWrj#9yh)Wah9#mL$B0g1_sL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_ET_2147789039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.ET!MTB"
        threat_id = "2147789039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 08 32 0c 16 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 75 ec 2b f0 03 f2 2b 35 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 8b 55 0c 88 0c 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_ET_2147789039_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.ET!MTB"
        threat_id = "2147789039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 81 e2 ff 00 00 00 8a 04 0e 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8a 04 0a 8a 13 32 d0 8b 44 24 ?? 45 88 13 04 00 8b 54 24}  //weight: 1, accuracy: Low
        $x_1_2 = "1Y4OG&ws&VDly>q>b)WvR3HcZ6IgrxNUIGb_70GtI&8eJ#*5@Ci*arF7HFp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EU_2147789040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EU!MTB"
        threat_id = "2147789040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 8a 04 30 34 e0 88 45 0f 8b de 85 f6 ?? ?? e8 ?? ?? ?? ?? 8b 4d 08 8a 45 0f 3b 75 fc ?? ?? 8a d3 2a d1 80 e2 e0 32 13 32 d0 88 13 03 df 3b 5d fc ?? ?? 46 ff 4d f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EU_2147789040_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EU!MTB"
        threat_id = "2147789040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 8b 45 ?? 0f af cb 03 4d f0 03 c1 8a 0c 3a 02 0d ?? ?? ?? ?? 30 08 ff 45 f0 8b 45 f0 3b 45 ?? 0f 82 03 00 89 55}  //weight: 1, accuracy: Low
        $x_1_2 = "@fGu+mnd$0%Oi5K3@Ad@vXgBHTQz!lpKya4BGdupxl(5qD8wSPeF)Tmyfk8eipXv#dT3(BmUI(Y90)rsWTQ(x+pGcXbD0QwmQ#yojqV?M144zT%^Hh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EV_2147789553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EV!MTB"
        threat_id = "2147789553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 0e 0f b6 04 0f 03 c2 33 d2 bb 05 18 00 00 f7 f3 a1 ?? ?? ?? ?? 03 55 e0 8d 14 42 03 55 dc 8b 45 f8 03 15 ?? ?? ?? ?? 40 03 15 ?? ?? ?? ?? 89 45 f8 8a 1c 0a 8b 55 fc 30 5c 02 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EV_2147789553_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EV!MTB"
        threat_id = "2147789553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 0f b6 04 01 8b 4d 0c 0f b6 14 11 33 d0 8b 45 f4 2b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 8b 4d 0c 88 14 01 e9}  //weight: 1, accuracy: Low
        $x_1_2 = "qB<SOTg@ievN_jJBIgTFadOe5bxA*qk^DFnG&EG1#n>Ts0a(g4*<MA$CD3XTSn59_ofuC1xux>+%SHFt<JBfXo38SHN6K5rAV)YmDR*4vcb6^sCR8OO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EY_2147792969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EY!MTB"
        threat_id = "2147792969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 11 0f b6 85 ?? ?? ?? ?? 33 d0 8b 8d ?? ?? ?? ?? 2b 8d ?? ?? ?? ?? 0f b6 c1 25 ff ?? ?? ?? 33 d0 8b 8d ?? ?? ?? ?? 88 11}  //weight: 1, accuracy: Low
        $x_1_2 = "Checking process of malware analysis tool: %s" ascii //weight: 1
        $x_1_3 = "joeboxcontrol.exe" ascii //weight: 1
        $x_1_4 = "joeboxserver.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EZ_2147793096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EZ!MTB"
        threat_id = "2147793096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 30 f6 d1 8b c6 3b 75 d4 73 ?? ?? 8a d0 2a d3 32 d1 30 10 03 c7 3b 45 d4 72 ?? 46 ff 4d fc 75}  //weight: 1, accuracy: Low
        $x_1_2 = "[ GOOD ]" ascii //weight: 1
        $x_1_3 = "\\2\\dll\\Release\\Test01.pdb" ascii //weight: 1
        $x_1_4 = "GetMouse" ascii //weight: 1
        $x_1_5 = "1.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_FA_2147793097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FA!MTB"
        threat_id = "2147793097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 08 0f b6 95 ?? ?? ?? ?? 33 ca 8b 85 ?? ?? ?? ?? 2b 85 ?? ?? ?? ?? 0f b6 d0 81 e2 ff ?? ?? ?? 33 ca 8b 85 ?? ?? ?? ?? 88 08}  //weight: 1, accuracy: Low
        $x_1_2 = "Checking process of malware analysis tool: %s" ascii //weight: 1
        $x_1_3 = "joeboxcontrol.exe" ascii //weight: 1
        $x_1_4 = "joeboxserver.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_RT_2147793131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.RT!MTB"
        threat_id = "2147793131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e2 8b 75 ?? 89 30 8b 45 ?? 89 01 8b 4d ?? 89 0a c7 45 ?? eb e9 1d dd e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_RT_2147793131_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.RT!MTB"
        threat_id = "2147793131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 8b 85 ?? ?? ?? ?? 0f b6 08 0f b6 95 ?? ?? ?? ?? 33 ca 8b 85 ?? ?? ?? ?? 2b 85 ?? ?? ?? ?? 0f b6 d0 81 e2 ff 00 00 00 33 ca 8b 85 ?? ?? ?? ?? 88 08 0f b7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_FB_2147793141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FB!MTB"
        threat_id = "2147793141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 02 0f b6 8d ?? ?? ?? ?? 33 c1 8b 95 ?? ?? ?? ?? 2b 95 ?? ?? ?? ?? 0f b6 ca 81 e1 ff ?? ?? ?? 33 c1 8b 95 ?? ?? ?? ?? 88 02}  //weight: 1, accuracy: Low
        $x_1_2 = "Checking process of malware analysis tool: %s" ascii //weight: 1
        $x_1_3 = "joeboxcontrol.exe" ascii //weight: 1
        $x_1_4 = "joeboxserver.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EX_2147793309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EX!MTB"
        threat_id = "2147793309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 11 0f b6 85 ?? ?? ?? ?? 33 d0 8b 8d ?? ?? ?? ?? 2b 8d ?? ?? ?? ?? 0f b6 c1 25 ff ?? ?? ?? 33 d0 8b 8d ?? ?? ?? ?? 88 11 0f b7 95 ?? ?? ?? ?? 52 8b 45 f8 50 ff 15 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 03 4d f0 89 8d ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_FC_2147793418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FC!MTB"
        threat_id = "2147793418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7c 24 18 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b c6 33 d2 b9 1f ?? ?? ?? f7 f1 8a 04 3e 8a 14 2a 32 c2 88 04 3e}  //weight: 1, accuracy: Low
        $x_1_2 = "Guh9dvGU7PXdZ2AXJqYeMqcLKfpSHU0Tsy77k28wNTOY5D6PZaDII3JtHd64Zm2BAkYWqeu2khHFuiANgemnoYZQPQmrbU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_FD_2147793419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FD!MTB"
        threat_id = "2147793419"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c powershell Set-MpPreference -DisableRealtimeMonitoring $true" ascii //weight: 1
        $x_1_2 = "/c sc stop WinDefend" ascii //weight: 1
        $x_1_3 = "DisableAntiSpyware" ascii //weight: 1
        $x_1_4 = "DisableScanOnRealtimeEnable" ascii //weight: 1
        $x_1_5 = "DisableOnAccessProtection" ascii //weight: 1
        $x_1_6 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_7 = "CPPdebugHook" ascii //weight: 1
        $x_1_8 = "\\lGBxsa\\jkhjkg\\hghj\\temp.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_FE_2147793420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FE!MTB"
        threat_id = "2147793420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 08 0f b6 95 ?? ?? ?? ?? 33 ca 8b 85 ?? ?? ?? ?? 2b 85 ?? ?? ?? ?? 0f b6 d0 81 e2 80 ?? ?? ?? 33 ca 8b 85 ?? ?? ?? ?? 88 08}  //weight: 1, accuracy: Low
        $x_1_2 = "DEHUGH EBST YDUSIJBDS OFDUIFVDGSHB" ascii //weight: 1
        $x_1_3 = "joeboxcontrol.exe" ascii //weight: 1
        $x_1_4 = "joeboxserver.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_FF_2147793577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FF!MTB"
        threat_id = "2147793577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 8a 82 ?? ?? ?? ?? 03 ca f6 d0 3b cf 73 ?? 8a d1 2a d3 32 11 32 d0 88 11 03 ce 3b cf 72 ?? 8b 55 f8 42 89 55 f8 3b d6 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_FG_2147793898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FG!MTB"
        threat_id = "2147793898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 0e 89 54 24 ?? 0f b6 d3 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 ?? 8a 18 8a 14 0a 32 da 88 18 8b 44 24 ?? 45 3b e8 72}  //weight: 1, accuracy: Low
        $x_1_2 = "N>E3JrW>39xDoBa*Br4nBL@KssJG8Mvb(X)hc*Q3)n(>@H*(8Z7z<Z2<n_23tkXlGhZ7oBw&D9Yi)Pqll!qBatDlWH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_FH_2147793982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FH!MTB"
        threat_id = "2147793982"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 0c 8a 04 06 32 04 0a 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 75 ec 2b 35 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 2b f2 2b 35 ?? ?? ?? ?? 03 f1 2b 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 8b 4d 0c 88 04 31 e9}  //weight: 1, accuracy: Low
        $x_1_2 = "nhd!QYb9OMaJl26!ZoR9^iDR0cGR<<8yv<5TP$ixm1g<Aso9#602o8N@xrI(rewcSY7BTwTBo$#th+jZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_FI_2147794042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FI!MTB"
        threat_id = "2147794042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d0 2b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b d0 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b d0 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b d0 2b 15 ?? ?? ?? ?? 8b 45 08 0f b6 14 10 8b 45 0c 0f b6 0c 08 33 ca 8b 55 f4}  //weight: 1, accuracy: Low
        $x_1_2 = "z4B5Ik#xX4I(gbfr?7Bckvy7FiTF3c7?VDzF)SZ%q+oVW)Y(U8CX$smU!%$DWgewGp6aWd8pYdV" ascii //weight: 1
        $x_1_3 = "pRg$EM&%B15PQ0*IH6zMe02sLZ<Fd*j<O7bCsr%Gr%nC(Ail>dtabmvyU4eNmoT7zd4Mcoj2H4Bpv*uiTc1QsQpun+5&o6cU(Ses+p^9q0#G&Na" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_FJ_2147794119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FJ!MTB"
        threat_id = "2147794119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b ca 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8b 55 08 0f b6 0c 0a 8b 55 0c 0f b6 04 02 33 c1 8b 4d f4 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8b 55 0c 88 04 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "y%(8rwOwk01SOX>tBA)_(ys5<b242(mbxK^%*T**EsQIu7uvm7>h+EYB3oBfJ&s?BZQoTweEx!BlRLL$jQ8o$#r2x12sF^uc!Hsd?m*SGbFa" ascii //weight: 1
        $x_1_3 = "&X+E*tca3TEvh0BPOM7+m*NM2*vUoYg*zk<I<mZz?wms*!h6WuV4cHPBfDCzpA(ePcR^_*e?s<cvq*R^kyhODHEDhEZUKj*XKf#xP1cIQZXc#_SPeCH4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_FK_2147794181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FK!MTB"
        threat_id = "2147794181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 03 c8 2b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 03 ca 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b c8 2b 0d ?? ?? ?? ?? 8b 55 f8 2b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b d0 2b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 8b 45 0c 8b 75 08 8a 0c 08 32 0c 16}  //weight: 1, accuracy: Low
        $x_1_2 = "z7u^YF>?DzwZfU>B+to!2CiyHyRxScUscAtkMGU>ReFPceEK#rg_qNBG<tM!4_rcNZ1AMTNn152?UYUOLxSlc*YNVan5w&" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_FL_2147794182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FL!MTB"
        threat_id = "2147794182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5d ec 2b 1d ?? ?? ?? ?? 2b 1d ?? ?? ?? ?? 03 df 2b 1d ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 03 fb 03 f7 2b 35 ?? ?? ?? ?? 03 f0 2b 35 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 2b f2 2b 35 ?? ?? ?? ?? 8b 55 0c 88 0c 32 e9}  //weight: 1, accuracy: Low
        $x_1_2 = "c0cb5>j)?z)ln$Krm5kD(i%+8MkpAJhK$^H09F" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_FM_2147794848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FM!MTB"
        threat_id = "2147794848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 4d f8 03 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 03 ca 2b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 2b ca 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8b 55 0c 8b 75 08 8a 04 02 32 04 0e 8b 4d ec}  //weight: 5, accuracy: Low
        $x_5_2 = {8b 55 0c 88 04 0a e9}  //weight: 5, accuracy: High
        $x_10_3 = "KhqNt_>gdwmxbG<KR&(Hsy)zv3erAM@CRw+nP8XdmMP^T0N2M6B^th#FmwZ@rQO@&RRfJv9Me2MMBl@3PfPUXn&aph+>N&dQY?ca@kQuzu(J5gMWI1H@" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_TrickBotCrypt_FN_2147794849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FN!MTB"
        threat_id = "2147794849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 55 0c 8b 75 08 8a 04 02 32 04 0e 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 75 ec 03 f2 2b f1}  //weight: 5, accuracy: Low
        $x_5_2 = {8b 4d 0c 88 04 31 e9}  //weight: 5, accuracy: High
        $x_10_3 = "%+tDKVR%3q%*&fBS!Irs<&Ef>r0?hD75_toQ%yCdjf0BxP$1(CItqTU@2v7%ajkQkO2UtOP0_IwP<>jy^ak&04" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_TrickBotCrypt_FO_2147794850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FO!MTB"
        threat_id = "2147794850"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 75 08 8a 04 08 32 04 16}  //weight: 5, accuracy: High
        $x_5_2 = {03 c8 8b 45 ?? 03 c8 8b 45 ?? 03 c8 8b 45 ?? 03 c8 8b 45 ?? 03 c8 8b 45 ?? 03 c8 03 cb 03 cf 03 ce 03 ca 8b 55 d0 03 55 0c 8a 45 eb 88 04 0a e9}  //weight: 5, accuracy: Low
        $x_10_3 = "nCHTbO2LeADv+4d<m7y(9%pudq>1dzUV1rh70T2cD6$HKwcUGFRNrD1+nH9PE$9PsomLsVih)g" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_TrickBotCrypt_FP_2147794851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FP!MTB"
        threat_id = "2147794851"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 0e 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 18 03 da 2b dd 8b 2d ?? ?? ?? ?? 03 dd 8a 14 0b 8a 18 32 da 8b 54 24 20 88 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_FQ_2147795080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FQ!MTB"
        threat_id = "2147795080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4d f8 03 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 03 ca 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8b 55 0c 8b 75 08 8a 04 02 32 04 0e 8b 4d ec 03 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 8b 55 0c 88 04 0a e9}  //weight: 10, accuracy: Low
        $x_10_2 = "DWaG$z@FG)j)Xn06Lz)B%mJtrC^*(y_I*v*E$1YK)CDZF4g!IIk2UrI%r+c8THwf?BovrtldVNb1" ascii //weight: 10
        $x_10_3 = "1fNha4k6t3cya$9ER#57^r(MSWrb6oTwBxK&mc48>CK6xSo(az7?7<*F#+@KP2b#HUi$UW%0#P#??mEag(L1Ne8hhwfQpN#g&" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_FR_2147795135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FR!MTB"
        threat_id = "2147795135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 11 03 c2 33 d2 f7 35 ?? ?? ?? ?? 89 55 f0 8b 45 f0 03 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 03 c1 2b 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 2b c2 2b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 8b 4d 08 0f b6 14 01 8b 45 0c 03 45 f4 0f b6 08 33 ca 8b 55 0c 03 55 f4 88 0a e9}  //weight: 10, accuracy: Low
        $x_10_2 = "t8%glP*_piyua1b<(4@ktjfXbiYux8V8)MrH?N9<)XJP8(v!feePIMKq4xI@At<15N_qTRRwZbgPH^?DQMR9jx^0W0F+L" ascii //weight: 10
        $x_10_3 = "gbP_+fo5$zS9*gz9bL3z?MEody*K0_#B+#6XCx@6DttY7S9*hJ2W(C^Y^2Jziy*<f!" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_FS_2147795255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FS!MTB"
        threat_id = "2147795255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 14 0f 03 c2 33 d2 f7 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b d8 0f af d8 4b 0f af d8 a1 ?? ?? ?? ?? 03 d3 2b d0 8b 44 24 ?? 8a 14 0a 8a 18 32 da 45 88 18}  //weight: 10, accuracy: Low
        $x_10_2 = "doUylYg<ad#zU0*1F!&5r>da!J^fdiLH+9aA?%w>Wsj5yQIDu@EqkuNizUADkPIHVZSL^SG282Fa?&P%ycA*kG%Vz_I+BT9VMa0@fg+VZFm+!61KI070DX3" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_FT_2147795256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FT!MTB"
        threat_id = "2147795256"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 41 08 8b 51 28 0b c7 85 d2 75 ?? 83 c8 04 6a 00 50 e8 ?? ?? ?? ?? 0f b6 4c 24 ?? 8b 15 ?? ?? ?? ?? 8a 14 11 8b 44 24 ?? 8b 4c 24 ?? 30 14 08 8b 4c 24 ?? 40 3b c1 89 44 24}  //weight: 5, accuracy: Low
        $x_5_2 = "e$#O@rk503b0h@yq_z6qmMc$y?uQM$?8r@R4R7f9TJv5x956RqxFu#" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_FU_2147795333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FU!MTB"
        threat_id = "2147795333"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 0c 89 4d f8 8b 0d ?? ?? ?? ?? 2b d9 6b c9 05 03 1d ?? ?? ?? ?? 03 5d fc 03 d8 8b 45 f4 0f b6 04 30 03 c2 33 d2 f7 35 ?? ?? ?? ?? 2b d1 03 d7 03 15 ?? ?? ?? ?? 8a 04 32 30 03}  //weight: 5, accuracy: Low
        $x_5_2 = "<R3a_c^mCNw4+^6Mle7<GHZIX9jim>EJW9<FL@1U@u7TkAW>$6uJbmk4#XvAPm$8" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_FV_2147795334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FV!MTB"
        threat_id = "2147795334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 14 0f 03 c2 33 d2 f7 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8d 04 80 2b d0 03 d5 8b 2d ?? ?? ?? ?? 03 d5 8b 6c 24 10 8a 14 0a 8a 45 00 32 c2 43 88 45 00 8b 44 24 20}  //weight: 5, accuracy: Low
        $x_5_2 = "1P+3FN?fe(EAiBbIV%qTj%Aj_LcB&s2pK9yYh#rIH<mIM&bX*m!^(p&ul^Q#*9>xBgam)3dYyHo^Du$F>z" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_FW_2147795406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FW!MTB"
        threat_id = "2147795406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 08 0f b6 14 10 8b 45 0c 0f b6 0c 08 33 ca 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 45 f4 2b c2 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 55 0c 88 0c 02}  //weight: 5, accuracy: Low
        $x_5_2 = "tP*Cs*?vIc<gJ081W3$slZGf95_VM+nkxYv3l4SHQYp@!bwqA>MA<" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_FX_2147795407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FX!MTB"
        threat_id = "2147795407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 04 37 8a 14 2e 03 c2 33 d2 f7 35 ?? ?? ?? ?? 03 ca 8b 15 ?? ?? ?? ?? 2b ca 8a 04 31 8a 0b 32 c8 8b 44 24 10 88 0b}  //weight: 5, accuracy: Low
        $x_5_2 = "D0ck*<>$GfUOJ2Yf)N_E<R^U2>mE!EQ***uTu*D_Xm%WrvS6N4l9p" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_FY_2147795408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FY!MTB"
        threat_id = "2147795408"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 14 10 8b 45 0c 0f b6 0c 08 33 ca 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 45 f4 2b c2 2b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 55 0c 88 0c 02}  //weight: 5, accuracy: Low
        $x_5_2 = "wtJWa8Biov0RYtU+!mnO+rNf*Dr@t<Y&kfZ+X94%a)4$f4&K" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_FZ_2147795468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.FZ!MTB"
        threat_id = "2147795468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 14 0e 03 c2 33 d2 f7 35 ?? ?? ?? ?? b8 02 00 00 00 2b 05 ?? ?? ?? ?? 0f af c5 0f af c5 48 0f af c5 03 da 03 c3 8a 14 08 8b 44 24 18 8a 18 32 da 8b 54 24 20 88 18}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_EW_2147797735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.EW!MTB"
        threat_id = "2147797735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b ca 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 2b ca 03 0d ?? ?? ?? ?? 8b 55 0c 8b 75 08 8a 04 02 32 04 0e 8b 4d ec 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8b 55 0c 88 04 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "L<k)ge%VZ4ZSmH6R4F^+ff0^Q04XiWK6y0vLg(o5Kbr6ZN0Nk_K<g)V+^YA<JTry*m!@MmBISU>z!!1!v5t@&5)S5JDfP#0h!2CeofWCnluD>@QP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_GA_2147797770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.GA!MTB"
        threat_id = "2147797770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 14 8a 04 32 8b 54 24 18 8a 14 3a 88 14 0e 8b 54 24 1c 88 04 3a 0f b6 14 0e 0f b6 04 0f 03 c2 33 d2 f7 f5 8b 6c 24 20 2b 15 ?? ?? ?? ?? 0f b6 04 0a 30 44 2b ff}  //weight: 1, accuracy: Low
        $x_1_2 = "ok_ya4>rBMwWs1Z2D4e*<eQN?DAp6u1mb!+X^r>qcp)?kaJNe7Ofiqpp#o*H_i" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_GB_2147797869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.GB!MTB"
        threat_id = "2147797869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 33 d2 f7 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2b d3 48 0f af 05 ?? ?? ?? ?? 03 fa 03 c7 8a 14 08 8b 44 24 18 8a 18 32 da 8b 54 24 20 88 18}  //weight: 1, accuracy: Low
        $x_1_2 = "9pWNWn<8Uo8C33iyD%7?Y3ZWf<WmCn9DlJzgWEUL(PBxJSey?8K*D<a?&Gxin0c10VL)?$)>V14igf6euUkxq%s*5OQLgwoL$LHkA<2i0rhn+4yLiCG8Ctg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_GC_2147798065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.GC!MTB"
        threat_id = "2147798065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 01 8b 4d 0c 0f b6 14 11 33 d0 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 0f af 35 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 0f af 3d ?? ?? ?? ?? 0f af 3d ?? ?? ?? ?? 03 7d f4 03 fe 2b 3d ?? ?? ?? ?? 2b 3d ?? ?? ?? ?? 03 f9 2b 3d ?? ?? ?? ?? 2b 3d ?? ?? ?? ?? 2b 3d ?? ?? ?? ?? 2b f8 8b 45 0c 88 14 38}  //weight: 1, accuracy: Low
        $x_1_2 = "gVt#(PqBPRUiAMPeLXNOKDcchaDdlhm4&oV4EQU3B&+Ytc_Gri&HF?*CjNUgpnwD$l^sky" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_GD_2147798238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.GD!MTB"
        threat_id = "2147798238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 d4 0f b6 02 0f b6 4d db 33 c1 8b 55 d4 2b 55 08 0f b6 ca 81 e1 e0 00 00 00 33 c1 8b 55 d4 88 02 8b 45 d4 03 45 e4 89 45 d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_GF_2147798425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.GF!MTB"
        threat_id = "2147798425"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 0a 33 d2 03 c3 f7 35 ?? ?? ?? ?? b8 02 00 00 00 2b c7 0f af c7 8b f9 03 fa 8a 14 38 8b 44 24 18 8a 18 32 da 8b 54 24 20 88 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_GG_2147798426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.GG!MTB"
        threat_id = "2147798426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f0 2b 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 2b d1 2b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 2b d1 2b 15 ?? ?? ?? ?? 8b 4d 08 0f b6 14 11 8b 4d 0c 0f b6 04 01 33 c2}  //weight: 1, accuracy: Low
        $x_1_2 = "33PbF@Ux4X@97z7@cHa6H8>hY7*?V7Qrs9#!1E?OsKBO>G8Q^EEx2AGIMD<5N&xbd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_GJ_2147799307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.GJ!MTB"
        threat_id = "2147799307"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 08 0f b6 55 ?? 33 ca 8b 45 ?? 2b 45 ?? 0f b6 d0 81 e2 e0 00 00 00 33 ca 8b 45 ?? 88 08 8b 4d ?? 03 4d ?? 89 4d ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_GK_2147805221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.GK!MTB"
        threat_id = "2147805221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0c 08 33 ca 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 0f af 35 ?? ?? ?? ?? 0f af 35 ?? ?? ?? ?? 8b 7d f4 2b fe 03 3d ?? ?? ?? ?? 03 3d ?? ?? ?? ?? 2b f8 2b 3d ?? ?? ?? ?? 2b fa 03 3d ?? ?? ?? ?? 03 3d ?? ?? ?? ?? 8b 55 0c 88 0c 3a}  //weight: 1, accuracy: Low
        $x_1_2 = "1QjX<WlEWzH_Y_gAXGg8Iu1iBzm0oyCiD!dIu&b(2uX1pUh0L3j35y@y6S0Tr7pN0rw2Be&2fXJy!gUP9sWx*SibqzZWixe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_GL_2147805222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.GL!MTB"
        threat_id = "2147805222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 0f 00 00 00 2b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 03 d3 2b 15 ?? ?? ?? ?? 83 c2 02 0f af d0 8b 44 24 1c 03 d5 03 c2 8b 54 24 10 8a 14 0a 02 15 ?? ?? ?? ?? 83 c5 01 30 10}  //weight: 1, accuracy: Low
        $x_1_2 = "LUXuRfAlXhrC^9cw)so?oGRtO9TsIOHsC+qxVW#MteX4H)a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_GM_2147805349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.GM!MTB"
        threat_id = "2147805349"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 0e 0f b6 c3 03 c7 33 d2 f7 35 ?? ?? ?? ?? 8b fa 8a 04 0f 88 04 0e 88 1c 0f 0f b6 04 0e 0f b6 d3 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 18 8a 1c 28 8a 14 0a 32 da 88 1c 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_GM_2147805349_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.GM!MTB"
        threat_id = "2147805349"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d1 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 2b d1 2b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 8b 4d 08 0f b6 14 11 8b 4d 0c 0f b6 04 01 33 c2 8b 4d f4 2b 0d ?? ?? ?? ?? 8b 55 0c 88 04 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "d+%7FM8MUeSH0_xH4)LqFl6D^D7wsqk4JxiPq0Vm@$?8mM&SjC<XQ9f7Lt+Kb>SRJQ9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_GO_2147807200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.GO!MTB"
        threat_id = "2147807200"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 32 03 c2 33 d2 f7 35 ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 41 0f af cf 03 d0 8b 44 24 18 03 ca 8a 10 8a 0c 31 32 d1 8b 4c 24 28 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = "gQ2v&dS>6p9Uw1%9J)#R1(o*C3cgLC1vFhNj02(lNCeNkoDq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_GP_2147807331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.GP!MTB"
        threat_id = "2147807331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 02 8b 45 ?? 0f b6 12 03 d8 0f b6 06 03 c2 99 be ?? ?? ?? ?? f7 fe 0f b6 c2 8a 04 08 30 03 ff 45 ?? 8b 45 ?? 3b 45 ?? 7c}  //weight: 1, accuracy: Low
        $x_1_2 = "qau!3BP2NZJ99nuDj#b_z0(KcJiIYDjdHxqX@bLN@ZI1T(UQQhc%chL!csdkairS3PHYC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_GR_2147807983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.GR!MTB"
        threat_id = "2147807983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d e4 3b 4d f4 73 ?? 8b 55 e4 0f b6 02 0f b6 4d eb 33 c1 8b 55 e4 2b 55 08 0f b6 ca 81 e1 ff 00 00 00 33 c1 8b 55 e4 88 02 8b 45 e4 03 45 f8 89 45 e4 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_GS_2147808201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.GS!MTB"
        threat_id = "2147808201"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d5 8b 6c 24 ?? 03 d5 8a 1c 3a 33 d2 03 c3 f7 35 ?? ?? ?? ?? 8b c7 03 c2 8a 0c 06 8b 44 24 ?? 8a 18 32 d9 8b 4c 24 ?? 88 18 8b 44 24 ?? 40 3b c1 89 44 24 ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = "9BGdhc_hH_VU6kyTq2_A4ld3xAVshW)*_pyRD&*n<2#o^vhSCzA44Uji^LoM9l" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_GT_2147808652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.GT!MTB"
        threat_id = "2147808652"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0c 08 33 ca 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 0f af 35 ?? ?? ?? ?? 0f af 35 ?? ?? ?? ?? 8b 7d f4 2b 3d ?? ?? ?? ?? 2b 3d ?? ?? ?? ?? 03 fe 03 c7 2b 05 ?? ?? ?? ?? 2b c2 8b 55 0c 88 0c 02}  //weight: 1, accuracy: Low
        $x_1_2 = ">X*qD2aSP9fcPBVWDT&p#2+bIkngbNih^e0uwD?TIH$Ork7gHsNEtY^Qp(ki7Pyv&s7dF$M!fl68vYJ0a*h_8hCx!U" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_GU_2147808801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.GU!MTB"
        threat_id = "2147808801"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 45 0f 8b 4d 08 83 c4 18 3b 75 ?? 73 15 ?? 8a d3 2a d1 80 e2 20 32 13 32 d0 88 13 03 df 3b 5d fc 72}  //weight: 10, accuracy: Low
        $x_1_2 = "PDSVSODnasbyvdgpniknasbdnghi" ascii //weight: 1
        $x_1_3 = "FLOCmathjanuary17122complex" ascii //weight: 1
        $x_1_4 = "SieletW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_TrickBotCrypt_GV_2147809038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.GV!MTB"
        threat_id = "2147809038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 e0 3b 45 f0 73 ?? 8b 4d e0 0f b6 11 0f b6 45 df 33 d0 8b 4d e0 2b 4d 08 0f b6 c1 83 e0 20 33 d0 8b 4d e0 88 11 8b 55 e0 03 55 fc 89 55 e0 eb}  //weight: 10, accuracy: Low
        $x_1_2 = "MASTERKEYVALUEPROVAES256" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_GW_2147809863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.GW!MTB"
        threat_id = "2147809863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 0f 88 04 0e 88 1c 0f 0f b6 04 0e 0f b6 d3 03 c2 33 d2 bb ?? ?? ?? ?? f7 f3 8b 45 ?? 40 89 45 ?? 0f b6 1c 0a 8b 55 ?? 30 5c 10 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_GX_2147809934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.GX!MTB"
        threat_id = "2147809934"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 14 3e 8b c6 83 e0 1f 8a 0c 28 32 d1 88 14 3e 46 3b f3 75}  //weight: 1, accuracy: High
        $x_1_2 = "Qa@fxYRz*N$4xu0Nl3$hyXD39IDS{24" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_YAB_2147897328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.YAB!MTB"
        threat_id = "2147897328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 4d e4 8b 4d 08 03 4d e8 0f b6 11 8b 45 e4 0f b6 8c 05 ?? ?? ?? ?? 33 d1 8b 45 18 03 45 e8 88 10 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBotCrypt_DK_2147899393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBotCrypt.DK!MTB"
        threat_id = "2147899393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 0a 02 d0 8b 44 24 ?? 8a 1c 28 32 da 88 1c 28 8b 44 24 ?? 45 3b e8 72 05 00 a0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

