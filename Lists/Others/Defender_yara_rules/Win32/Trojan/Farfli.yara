rule Trojan_Win32_Farfli_PF_2147709189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.PF"
        threat_id = "2147709189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b e5 5d 8a 10 8a 19 32 da 88 19 90 55 8b ec 83 c4 0c 83 ec 0c 8b e5 90 5d 8a 10 8a 19 02 da 88 19}  //weight: 1, accuracy: High
        $x_1_2 = {53 5b 90 8b e5 90 5d 33 c9 c6 45 fc 52 66 89 4d fd c6 45 fd 75 88 4d ff c6 45 fe 6e 90 55 8b ec 41 49 83 c4 09 83 ec 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_DSK_2147752581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DSK!MTB"
        threat_id = "2147752581"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 08 8a 4d 13 8a 10 32 d1 02 d1 88 10 40 89 45 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RSK_2147753848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RSK!MTB"
        threat_id = "2147753848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 1c 30 8b 55 10 30 1c 32 8a 14 32 30 14 30 8a 14 30 8b 5d 10 30 14 33 48 ff 45 10 8b d0 2b 55 10 83 fa 01 7d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_PA_2147754829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.PA!MTB"
        threat_id = "2147754829"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 08 88 4d f0 8b 55 08 03 55 fc 8b 45 08 03 45 f8 8a 08 88 0a 8b 55 08 03 55 f8 8a 45 f0 88 02 8b 4d 08 03 4d fc 33 d2 8a 11 8b 45 08 03 45 f8 33 c9 8a 08 03 d1 81 e2 ff 00 00 80 79}  //weight: 1, accuracy: High
        $x_1_2 = {4a 81 ca 00 ff ff ff 42 89 55 f4 8b 55 0c 03 55 ec 8b 45 08 03 45 f4 8a 0a 32 08 8b 55 0c 03 55 ec 88 0a e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_A_2147756642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.A!MTB"
        threat_id = "2147756642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ce e8 ?? ?? ?? ?? 8b e8 85 ed ?? ?? 8b 46 04 55 50 53 ?? ?? ?? ?? ?? ?? 83 c4 0c 8b 46 04 85 c0}  //weight: 2, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "Applications\\iexplore.exe\\shell\\open\\command" ascii //weight: 1
        $x_2_4 = "kinh.xmcxmr.com" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_GC_2147760613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.GC!MTB"
        threat_id = "2147760613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 1c 32 89 55 ?? 8d 04 32 8b 45 ?? 03 c8 0f b6 04 37 0f b6 d3 03 c2 [0-48] 8a 04 32 30 01 ff 45 ?? 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_GC_2147760613_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.GC!MTB"
        threat_id = "2147760613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\xhjmjj.dat" ascii //weight: 1
        $x_1_2 = "c:\\Win_lj.ini" ascii //weight: 1
        $x_1_3 = "Net-Temp.ini" ascii //weight: 1
        $x_1_4 = "%SystemRoot%\\System32\\svchost.exe -k sougou" ascii //weight: 1
        $x_1_5 = "TOXHJ MYLOVE" ascii //weight: 1
        $x_1_6 = "wldlog.dll" ascii //weight: 1
        $x_1_7 = "Xhjmj Shenji" ascii //weight: 1
        $x_1_8 = "Mjjxhj__Bjnl" ascii //weight: 1
        $x_1_9 = "softWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_GKM_2147779948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.GKM!MTB"
        threat_id = "2147779948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 10 80 f2 3d 80 c2 3d 88 10 83 c0 01 83 e9 01 75}  //weight: 1, accuracy: High
        $x_1_2 = {8b f8 8b 46 ?? 03 44 24 ?? 52 50 57 e8 ?? ?? ?? ?? 89 7e ?? 83 c4 0c 8b 4c 24 ?? 8b 11 8b 44 24 ?? 0f b7 4a ?? 83 c0 01 83 c6 28 3b c1 89 44 24 ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_GA_2147782759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.GA!MTB"
        threat_id = "2147782759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 08 80 f1 3d 80 c1 3d 88 08 83 c0 01 83 ee 01 75}  //weight: 10, accuracy: High
        $x_10_2 = {5c c6 44 24 ?? 53 c6 44 24 ?? 56 c6 44 24 ?? 50 c6 44 24 ?? 37 c6 44 24 ?? 2e c6 44 24 ?? 50 c6 44 24 ?? 4e c6 44 24 ?? 47 c6 44 24 ?? 00 ff d5}  //weight: 10, accuracy: Low
        $x_1_3 = "SVP7.PNG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MES_2147788930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MES!MTB"
        threat_id = "2147788930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 08 03 55 fc 8a 02 04 86 8b 4d 08 03 4d fc 88 01 8b 55 08 03 55 fc 8a 02 34 ?? 8b 4d 08 03 4d fc 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_EGZV_2147793439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.EGZV!MTB"
        threat_id = "2147793439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 83 fe 02 75 02 33 f6 8a 14 39 0f b7 c6 80 ea 7a 8a 44 45 fc 32 c2 46 88 04 39 41 3b 4d 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MESS_2147793772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MESS!MTB"
        threat_id = "2147793772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e 0d 0d 0a 24 ?? ?? ?? ?? ?? ?? ?? ce 11 3d fa 8a 70 53 a9 8a 70 53 a9 8a 70 53 a9 49 7f 0e a9 80 70 53 a9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MA_2147794526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MA!MTB"
        threat_id = "2147794526"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 0c b9 fe 00 00 00 25 ff 00 00 00 56 99 f7 f9 8b 74 24 0c 80 c2 08 85 f6 76 10 8b 44 24 08 8a 08 32 ca 02 ca 88 08 40 4e 75 f4}  //weight: 1, accuracy: High
        $x_1_2 = {8a 50 01 40 80 fa 22 74 29 84 d2 74 25 0f b6 d2 f6 82}  //weight: 1, accuracy: High
        $x_1_3 = {ff 01 85 f6 74 d5 8a 10 88 16 46 eb ce}  //weight: 1, accuracy: High
        $x_1_4 = {88 84 05 ec ?? ?? ?? 40 3b c6 72 f4 8a 45 ?? c6 85 ec ?? ?? ?? ?? 84 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MA_2147794526_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MA!MTB"
        threat_id = "2147794526"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {f5 56 86 de fb 3e 34 3b d6 48 dc ea 07 cb 4c f0 50 c9 d0 89 f8 6a ca 1a 3d 7f e1 dd 2d 83 0b 9d}  //weight: 5, accuracy: High
        $x_5_2 = {4a 70 9f 20 59 4a dd 0d 38 76 8b ca be 19 64 de 7b ea 83 81 d9 d8 fd 9d d5 be 6a 93 cf 54 9c 22}  //weight: 5, accuracy: High
        $x_5_3 = {38 77 56 57 eb c0 51 a3 df 56 5b 23 f5 02 c1 a3 3d cd b2 94 31 1e 95 15 4e 46 34 33 c6 04 61 28}  //weight: 5, accuracy: High
        $x_1_4 = "InitCommonControls" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_DT_2147794589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DT!MTB"
        threat_id = "2147794589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d fc 80 04 11 7a 03 ca 8b 4d fc 80 34 11 59 03 ca 42 3b d0 7c e9}  //weight: 1, accuracy: High
        $x_1_2 = {8b 54 24 08 53 8a 1a 88 19 41 42 84 db 75 f6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_DZ_2147794590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DZ!MTB"
        threat_id = "2147794590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jesso.3322.org" ascii //weight: 1
        $x_1_2 = "c:\\Windows\\%s%d.exe" ascii //weight: 1
        $x_1_3 = "c:\\Windows\\BJ.exe" ascii //weight: 1
        $x_1_4 = "GetTickCount" ascii //weight: 1
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_DX_2147794591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DX!MTB"
        threat_id = "2147794591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://users.qzone.qq.com/fcg-bin/cgi_get_portrait.fcg?" ascii //weight: 1
        $x_1_2 = "DUB.exe" ascii //weight: 1
        $x_1_3 = "S.exe" ascii //weight: 1
        $x_1_4 = "YY.exe" ascii //weight: 1
        $x_1_5 = "V3Svc.exe" ascii //weight: 1
        $x_1_6 = "Game Over QQ : 4648150" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ZQ_2147794593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ZQ!MTB"
        threat_id = "2147794593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 ec 8a 1c 11 80 c3 7a 88 1c 11 8b 55 ec 8a 1c 11 80 f3 59 88 1c 11 41 3b c8 7c e3}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 0c 40 8a 0a 42 88 48 ff 84 c9 74 0a}  //weight: 1, accuracy: High
        $x_1_3 = "skybluehacker@yahoo.com.cn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MC_2147795095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MC!MTB"
        threat_id = "2147795095"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 74 24 18 8b 57 54 8b f8 53 8b 4e 3c 03 ca 8b d1 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 8b 4c 24 1c 8b 74 24 14 56 51 8b 51 3c 03 c2 89 03 89 68 34}  //weight: 1, accuracy: High
        $x_1_2 = {8a 14 08 8b 2f 8b da 81 e3 ?? ?? ?? ?? 03 dd 03 f3 81 e6 ?? ?? ?? ?? 79 08 4e 81 ce ?? ?? ?? ?? 46 8a 1c 0e 83 c7 04 88 1c 08 40 3d ?? ?? ?? ?? 88 14 0e 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MC_2147795095_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MC!MTB"
        threat_id = "2147795095"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {a9 94 39 11 ed f5 57 42 ed f5 57 42 ed f5 57 42 82 ea 5c 42 e4 f5 57 42 82 ea 5d 42 eb f5 57 42 6e e9 59 42 c1 f5 57 42 96 e9 5b 42 e8 f5 57 42}  //weight: 5, accuracy: High
        $x_2_2 = "Cookie: %s" ascii //weight: 2
        $x_2_3 = "anonymous@123.com" ascii //weight: 2
        $x_2_4 = "\\shell\\open\\command" ascii //weight: 2
        $x_1_5 = "GetScrollPos" ascii //weight: 1
        $x_1_6 = "IsWow64Process" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BE_2147795103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BE!MTB"
        threat_id = "2147795103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Debug\\Eidolon.exe" ascii //weight: 1
        $x_1_2 = "EidolonRun" ascii //weight: 1
        $x_1_3 = "www.xy999.com" ascii //weight: 1
        $x_1_4 = "EidolonDlg" ascii //weight: 1
        $x_1_5 = "Eidolon.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_CS_2147795471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.CS!MTB"
        threat_id = "2147795471"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NisSrv.exe" ascii //weight: 1
        $x_1_2 = "%s\\%s.exe" ascii //weight: 1
        $x_1_3 = "UnThreat.exe" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_5 = "ad-watch.exe" ascii //weight: 1
        $x_1_6 = "avcenter.exe" ascii //weight: 1
        $x_1_7 = "knsdtray.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AA_2147795841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AA!MTB"
        threat_id = "2147795841"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 08 03 55 0c 33 c0 8a 42 ff 89 45 e8 8b 4d e8 c1 e9 05 8b 55 ec c1 e2 02 33 ca 8b 45 ec c1 e8 03 8b 55 e8 c1 e2 04 33 c2 03 c8 8b 45 f4 33 45 ec 8b 55 f8 83 e2 03 33 55 f0 8b 75 10 8b 14 96 33 55 e8 03 c2 33 c8 8b 45 08 8a 10 2a d1 8b 45 08 88 10 8b 4d 08 33 d2 8a 11 89 55 ec 8b 45 f4 05 47 86 c8 61 89 45 f4 8b 4d fc 83 e9 01 89 4d fc 83 7d fc 00 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = "www.xy999.com" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_CV_2147796158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.CV!MTB"
        threat_id = "2147796158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 50 6a eb 01 40 27 80 38 e8 30 04 c6 cc 1a 48 16 5c f6 f7 7c 40 01 07 0f b6 1e 88 18 46 90 34 3e 29 f4 47 25 ec c9 0c 44 24 1c 61 cc 75 60}  //weight: 1, accuracy: High
        $x_1_2 = {cd 07 ad c1 c8 b0 35 87 36 2a 74 56 75 f2}  //weight: 1, accuracy: High
        $x_1_3 = {67 42 a2 e4 28 22 69 32 4d 14 1b 44 e8 8d 35 9d 17 19 0b 43 dc 34 9c 7f 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_CV_2147796158_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.CV!MTB"
        threat_id = "2147796158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:Windows88.exe" ascii //weight: 1
        $x_1_2 = "203.160.54.250/9" ascii //weight: 1
        $x_1_3 = "@fuck" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AF_2147796160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AF!MTB"
        threat_id = "2147796160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 8a 08 32 4d ec 8b 55 08 88 0a 8b 45 08 8a 08 02 4d ec 8b 55 08 88 0a b8 4e 1e 40 00 c3 c7 45 fc 01 00 00 00 8b 45 08 83 c0 01 89 45 08 eb 99}  //weight: 1, accuracy: High
        $x_1_2 = {8b c7 8b cf c1 f8 05 83 e1 1f 8b 04 85 a0 1d 43 00 8d 04 c8 8b 0b 89 08 8a 4d 00 88 48 04 47 45 83 c3 04 3b fe 7c ba}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AB_2147796537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AB!MTB"
        threat_id = "2147796537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 74 24 0c 80 c2 21 85 f6 76 10 8b 44 24 08 8a 08 32 ca 02 ca 88 08 40 4e 75 f4}  //weight: 1, accuracy: High
        $x_1_2 = {8b 0b 8b 73 04 8b 7c 24 18 8b d1 03 f7 8b f8 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 89 43 f8 8b 4c 24 20 8b 44 24 10 40 83 c3 28 8b 11 33 c9 89 44 24 10 66 8b 4a 06 3b c1 0f 8c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AB_2147796537_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AB!MTB"
        threat_id = "2147796537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {bb e9 7e f3 64 48 09 57 56 53 ff d0 08 0c e8 15 ff 00 bb db fb 5c 82 b0 4e 0f 24 0a 4c 33 89 45 af b9 dd}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AB_2147796537_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AB!MTB"
        threat_id = "2147796537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 2a 2c 0a 00 68 38 ?? 0d 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 a3 00 00 00 00 58 58 58 58 8b e8 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AB_2147796537_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AB!MTB"
        threat_id = "2147796537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f3 0f 6f 84 05 3c 98 f0 ff 66 0f ef c1 f3 0f 7f 84 05 3c 98 f0 ff 83 c0 10 3d c0 67 0f 00 75 e0}  //weight: 1, accuracy: High
        $x_1_2 = "File created successfully." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AG_2147796538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AG!MTB"
        threat_id = "2147796538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 3c 11 8b 55 08 0f b6 04 02 99 bb ?? ?? ?? 00 f7 fb ff 45 08 b8 cd ?? ?? ?? 80 c2 36 30 17 f7 e1 c1 ea 03 8d 04 92 03 c0 8b d1 2b d0 75 03 89 55 08 8b 45 0c 41 3b c8 7c}  //weight: 3, accuracy: Low
        $x_2_2 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a ff 50 ff 15 ?? ?? ?? ?? 68 2c 01 00 00 ff 15 ?? ?? ?? ?? 32 c0 c3 cc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MB_2147796698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MB!MTB"
        threat_id = "2147796698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b0 6b b1 61 88 44 24 43 88 44 24 44 b0 20 b2 2f c6 44 24 40 74 88 4c 24 41 c6 44 24 42 73 88 5c 24 45 c6 44 24 46 6c c6 44 24 47 6c 88 44 24 48 88 54 24 49 c6 44 24 4a 66 88 44 24 4b 88 54 24 4c 88 5c 24 4d c6 44 24 4e 6d 88 44 24 4f}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\%ssvchast.exe" ascii //weight: 1
        $x_1_3 = "Sleep" ascii //weight: 1
        $x_1_4 = "GetAsyncKeyState" ascii //weight: 1
        $x_1_5 = "[CLEAR]" ascii //weight: 1
        $x_1_6 = "[BACKSPACE]" ascii //weight: 1
        $x_1_7 = "[Down]" ascii //weight: 1
        $x_1_8 = "[Right]" ascii //weight: 1
        $x_1_9 = "[Left]" ascii //weight: 1
        $x_1_10 = "[End]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MB_2147796698_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MB!MTB"
        threat_id = "2147796698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 56 8b 75 10 57 8b 4e 04 8b 7d 0c 8b 46 08 03 cf 3b c8 7c 23 41 03 c0 3b c1 0f 4f c8 51}  //weight: 5, accuracy: High
        $x_2_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" wide //weight: 2
        $x_2_3 = "Local\\minerfucker" wide //weight: 2
        $x_2_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide //weight: 2
        $x_1_5 = "CryptEncrypt" ascii //weight: 1
        $x_1_6 = "GetThreadPriority" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MD_2147796699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MD!MTB"
        threat_id = "2147796699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "PKVgsNtwNalBNzqlVoitVKEkjTIBppkz" ascii //weight: 5
        $x_5_2 = "vlyOWOKuhRCPZHeqiazbJGhAxNKaydve" ascii //weight: 5
        $x_1_3 = ".symtab" ascii //weight: 1
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
        $x_1_5 = "SwitchToThread" ascii //weight: 1
        $x_1_6 = "SetThreadContext" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MD_2147796699_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MD!MTB"
        threat_id = "2147796699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c6 45 dd 59 c6 45 de 53 c6 45 df 54 c6 45 e0 45 c6 45 e1 4d c6 45 e2 5c c6 45 e3 43 c6 45 e4 75 c6 45 e5 72 c6 45 e6 72 c6 45 e7 65 c6 45 e8 6e c6 45 e9 74 c6 45 ea 43 c6 45 eb 6f c6 45 ec 6e c6 45 ed 74 c6 45 ee 72 c6 45 ef 6f c6 45 f0 6c c6 45 f1 53 c6 45 f2 65 c6 45 f3 74 c6 45 f4 5c c6 45 f5 53 c6 45 f6 65 c6 45 f7 72 c6 45 f8 76 c6 45 f9 69 c6 45 fa 63 c6 45 fb 65 c6 45 fc 73 c6 45 fd 5c 88 ?? fe}  //weight: 10, accuracy: Low
        $x_1_2 = "Serpiei" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ME_2147796701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ME!MTB"
        threat_id = "2147796701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c6 45 ed 53 c6 45 ee 48 c6 45 ef 45 c6 45 f0 4c c6 45 f1 4c c6 45 f2 2e c6 45 f3 54 c6 45 f4 58 c6 45 f5 54 c6 45 f6 00 8d 4d dc 51 68 ?? ?? ?? ?? e8}  //weight: 5, accuracy: Low
        $x_3_2 = "SuperMarkets.EXE" wide //weight: 3
        $x_1_3 = "SetCapture" ascii //weight: 1
        $x_1_4 = "ScreenToClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ME_2147796701_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ME!MTB"
        threat_id = "2147796701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 8b 7c 24 0c 33 c9 85 ff 7e ?? 53 56 8b 74 24 10 8b c1 bb 03 00 00 00 99 f7 fb 8a 04 31 83 fa 01 75 ?? 3c 20 7e ?? 3c 7f 7d ?? fe c8 eb ?? 3c 20 7e ?? 3c 7f 7d ?? fe c0 88 04 31 41 3b cf 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 41 00 00 00 33 c0 8d 7c 24 64 8d 54 24 64 f3 ab bf ?? ?? ?? ?? 83 c9 ff f2 ae f7 d1 2b f9 c7 44 24 60 00 00 00 00 8b c1 8b f7 8b fa c1 e9 02 f3 a5 8b c8 33 c0 83 e1 03 f3 a4 8d 7c 24 64 83 c9 ff f2 ae f7 d1 49 51 8d 4c 24 68 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MH_2147796714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MH!MTB"
        threat_id = "2147796714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 40 8b cf 99 f7 f9 8a 1c 32 89 55 08 8d 04 32 89 45 f4 0f b6 c3 03 45 f8 99 f7 f9 8b 45 f4 89 55 f8 8d 0c 32 8a 14 32 88 10 8b 55 fc 88 19 8b 4d 0c 0f b6 00 03 ca 0f b6 d3 03 c2 8b df 99 f7 fb 8a 04 32 30 01 ff 45 fc 8b 45 fc 3b 45 10 72}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 08 8b 55 10 8b f9 83 45 10 04 8a 1c 30 0f b6 c3 03 02 03 45 fc 99 f7 ff 8a 04 32 89 55 fc 8d 3c 32 8b 55 08 ff 45 08 39 4d 08 88 04 32 88 1f 7c}  //weight: 1, accuracy: High
        $x_1_3 = {8b c3 33 d2 f7 75 10 8b 45 0c 88 1c 33 43 0f b6 04 02 89 07 83 c7 04 3b d9 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MH_2147796714_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MH!MTB"
        threat_id = "2147796714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = ":\\Windows\\DNomb\\Mpec.mbt" ascii //weight: 5
        $x_1_2 = "://whtty.oss-cn-hongkong.aliyuncs.com" ascii //weight: 1
        $x_1_3 = "cmd.exe /c del" ascii //weight: 1
        $x_1_4 = "\\shell\\open\\command" ascii //weight: 1
        $x_1_5 = "Ctrl+PageDown" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_CQ_2147796823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.CQ!MTB"
        threat_id = "2147796823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "haidishijie.3322.org" ascii //weight: 1
        $x_1_2 = "c:\\Windows\\%s%d.exe" ascii //weight: 1
        $x_1_3 = "c:\\Windows\\BJ.exe" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_5 = "GetTickCount" ascii //weight: 1
        $x_1_6 = "unknown compression method" ascii //weight: 1
        $x_1_7 = "SHGetSpecialFolderPathA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_CT_2147796944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.CT!MTB"
        threat_id = "2147796944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 0c f7 d8 89 45 0c b8 34 00 00 00 99 f7 7d 0c 83 c0 06 89 45 fc 8b 4d fc 69 c9 b9 79 37 9e 89 4d f4 8b 55 08 33 c0 8a 02 89 45 ec 8b 4d f4 c1 e9 02 83 e1 03 89 4d f0 8b 55 0c 83 ea 01 89 55 f8 eb 09 8b 45 f8 83 e8 01 89 45 f8 83 7d f8 00 76 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_FA_2147797671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.FA!MTB"
        threat_id = "2147797671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 10 a7 e5 9c a1 8d 1d 98 4a aa 65 31 14 be 31 a4 b3 80 41 ef e6 74 a8 84 50 25 27 a9 73 de 71 70}  //weight: 1, accuracy: High
        $x_1_2 = "c:\\%s.exe" ascii //weight: 1
        $x_1_3 = "DoVirusScan" ascii //weight: 1
        $x_1_4 = "http://192.168.100.83" ascii //weight: 1
        $x_1_5 = "http://www.1.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AW_2147797755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AW!MTB"
        threat_id = "2147797755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 8a 14 01 8b da 81 e3 ff 00 00 00 03 f3 81 e6 ff 00 00 80 79 08 4e 81 ce 00 ff ff ff 46 8a 1c 06 88 54 24 18 88 1c 01 8b 5c 24 18 88 14 06 33 d2 8a 14 01 81 e3 ff 00 00 00 03 d3 81 e2 ff 00 00 80 79 08 4a 81 ca 00 ff ff ff 42 8a 14 02 8a 1c 2f 32 da 8b 54 24 1c 88 1c 2f 47 3b fa 72 90}  //weight: 1, accuracy: High
        $x_1_2 = {8a 14 08 8b 2f 8b da 81 e3 ff 00 00 00 03 dd 03 f3 81 e6 ff 00 00 80 79 08 4e 81 ce 00 ff ff ff 46 8a 1c 0e 83 c7 04 88 1c 08 40 3d 00 01 00 00 88 14 0e 7c cb}  //weight: 1, accuracy: High
        $x_1_3 = {8b 0b 8b 73 04 8b 7c 24 18 8b d1 03 f7 8b f8 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 89 43 f8 8b 4c 24 20 8b 44 24 10 40 83 c3 28 8b 11 33 c9 89 44 24 10 66 8b 4a 06 3b c1 0f 8c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_FG_2147797997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.FG!MTB"
        threat_id = "2147797997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 5c 24 10 02 d1 8b 4c 24 28 83 e6 03 33 f5 8a 0c b1 32 4c 24 18 8b 6c 24 10 32 d8 02 cb 32 d1 28 17 0f b6 07 81 c5 47 86 c8 61 83 6c 24 14 01 89 6c 24 10 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = "DatePickerDemo.EXE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_DFD_2147799513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DFD!MTB"
        threat_id = "2147799513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 44 1e 01 8a 14 39 46 32 d0 8b c1 88 14 39 99 bd 05 00 00 00 f7 fd 85 d2 75 02 33 f6 8b 44 24 18 41 3b c8 7c da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AH_2147805263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AH!MTB"
        threat_id = "2147805263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "MFCApplication1.AppID.NoVersion" ascii //weight: 3
        $x_3_2 = "fuckyou" ascii //weight: 3
        $x_3_3 = "Users\\MRK" ascii //weight: 3
        $x_3_4 = "8088wwc220318vs2022MFC" ascii //weight: 3
        $x_3_5 = "MFCApplication1.pdb" ascii //weight: 3
        $x_3_6 = "SleepConditionVariableCS" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MO_2147805567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MO!MTB"
        threat_id = "2147805567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 e8 83 c2 01 89 55 e8 8b 45 e8 3b 45 0c 73 ?? 8b 4d 08 8a 11 32 55 ec 8b 45 08 88 10 8b 4d 08 8a 11 02 55 ec 8b 45 08 88 10 8b 4d 08 83 c1 01 89 4d 08 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {56 8b 74 24 0c 57 56 e8 ?? ?? ?? ?? ff 4e 04 59 78 0f 8b 0e 8a 44 24 0c 0f b6 f8 88 01 ff 06 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_CBG_2147806312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.CBG!MTB"
        threat_id = "2147806312"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Consys21.dll" ascii //weight: 1
        $x_1_2 = "http://users.qzone.qq.com/fcg-bin/cgi_get_portrait.fcg?uins" ascii //weight: 1
        $x_1_3 = "Server\\Debug\\DHL2012.pdb" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
        $x_1_6 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MR_2147807601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MR!MTB"
        threat_id = "2147807601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ResSkin.exe" ascii //weight: 1
        $x_1_2 = "MYTYPE" ascii //weight: 1
        $x_1_3 = "TRACKBAR" wide //weight: 1
        $x_1_4 = "cef_browser_host_create_browser_sync" ascii //weight: 1
        $x_1_5 = "cef_base64decode" ascii //weight: 1
        $x_1_6 = "cef_base64encode" ascii //weight: 1
        $x_1_7 = "cef_get_path" ascii //weight: 1
        $x_1_8 = "cef_set_crash_key_value" ascii //weight: 1
        $x_1_9 = "cef_shutdown" ascii //weight: 1
        $x_1_10 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_11 = "GetKeyState" ascii //weight: 1
        $x_1_12 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_13 = "GetAsyncKeyState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MP_2147807760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MP!MTB"
        threat_id = "2147807760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Server.Dat" ascii //weight: 1
        $x_1_2 = "EnableIdleHook" ascii //weight: 1
        $x_1_3 = "EnableKeyboardHook" ascii //weight: 1
        $x_1_4 = "EnableTaskMgr" ascii //weight: 1
        $x_1_5 = "Speed.exe" ascii //weight: 1
        $x_1_6 = "fuckyou" ascii //weight: 1
        $x_1_7 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_8 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_FC_2147807786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.FC!MTB"
        threat_id = "2147807786"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b c8 8a 14 01 30 10 40 4e 75 f7}  //weight: 1, accuracy: High
        $x_1_2 = {8b 54 24 08 8a 14 16 8b ce 83 e1 07 8b c6 d2 e2 c1 f8 03 03 c7 08 10 46 83 fe 40 7c e3}  //weight: 1, accuracy: High
        $x_1_3 = {8a 1c 30 8b 55 10 30 1c 32 8a 14 32 30 14 30 8a 14 30 8b 5d 10 30 14 33 48 ff 45 10 8b d0 2b 55 10 83 fa 01 7d da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MJ_2147808461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MJ!MTB"
        threat_id = "2147808461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "111.cf599.com" ascii //weight: 1
        $x_1_2 = "C:\\WINDOWS\\SYSTEM32\\explor.exe" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "C:\\documents and settings\\ All users\\start menu\\programs\\start up\\explor.exe" ascii //weight: 1
        $x_1_5 = "192.168.1.244" ascii //weight: 1
        $x_1_6 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MM_2147808462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MM!MTB"
        threat_id = "2147808462"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\Program Files\\NT_Path.gif" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" ascii //weight: 1
        $x_1_3 = "MXIANG" ascii //weight: 1
        $x_1_4 = "SYSTEM\\CurrentControlSet\\Services\\RemoteAccess\\RouterManagers\\Ip" ascii //weight: 1
        $x_1_5 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\Wds\\rdpwd\\Tds\\tcp" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_7 = "CallNextHookEx" ascii //weight: 1
        $x_1_8 = "SetClipboardData" ascii //weight: 1
        $x_1_9 = "Sleep" ascii //weight: 1
        $x_1_10 = "GetKeyNameTextA" ascii //weight: 1
        $x_1_11 = "FindResourceA" ascii //weight: 1
        $x_1_12 = "SizeofResource" ascii //weight: 1
        $x_1_13 = "LoadResource" ascii //weight: 1
        $x_1_14 = "LockResource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MV_2147808966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MV!MTB"
        threat_id = "2147808966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 0c 73 ?? 8b 4d f4 e8 ?? ?? ?? ?? 88 45 fb 0f b6 55 fb 8b 45 08 03 45 fc 0f b6 08 33 d1 8b 45 08 03 45 fc 88 10 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 4c 0e 08 88 4c 02 08 8b 55 f8 8b 42 04 8b 4d f8 8a 55 ff 88 54 01 08 8b 45 f8 8b 48 04 8b 55 f8 0f b6 44 0a 08 8b 4d f8 8b 11 8b 4d f8 0f b6 54 11 08 03 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_TI_2147809196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.TI!MTB"
        threat_id = "2147809196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 08 32 ca 02 ca 88 08 40 4e 75 f4}  //weight: 1, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RPZ_2147809255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RPZ!MTB"
        threat_id = "2147809255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 11 02 d0 32 d0 02 d0 32 d0 88 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RPZ_2147809255_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RPZ!MTB"
        threat_id = "2147809255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 10 8b 40 10 33 ff 03 c2 33 d2 8b c8 2b ce 3b f0 0f 47 ca 89 4d 0c 85 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RPZ_2147809255_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RPZ!MTB"
        threat_id = "2147809255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c9 76 11 8d 44 24 0c 50 52 51 8b 4f e4 51 ff 15 ?? ?? ?? ?? 8b 13 0f b7 42 06 45 83 c7 28 3b e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RPZ_2147809255_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RPZ!MTB"
        threat_id = "2147809255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 28 4b c6 44 24 2a 52 c6 44 24 2b 4e c6 44 24 2d 4c c6 44 24 2e 33 c6 44 24 2f 32 c6 44 24 30 2e c6 44 24 31 64 88 44 24 32 88 44 24 33 c6 44 24 34 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MS_2147809308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MS!MTB"
        threat_id = "2147809308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sfwu.3322.org" ascii //weight: 1
        $x_1_2 = "Scroll" ascii //weight: 1
        $x_1_3 = "Num Lock" ascii //weight: 1
        $x_1_4 = "Insert" ascii //weight: 1
        $x_1_5 = "Snapshot" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Classes\\.386" ascii //weight: 1
        $x_1_7 = {8d 95 6c ff ff ff 52 6a 00 68 03 00 1f 00 ff 15 ?? ?? ?? ?? 8b f0 85 f6 75 ?? 68 c8 00 00 00 ff 15 ?? ?? ?? ?? 47 81 ff e8 03 00 00 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_CBF_2147810302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.CBF!MTB"
        threat_id = "2147810302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sfwu.3322.org" ascii //weight: 1
        $x_1_2 = "c:\\Windows\\%s%d.exe" ascii //weight: 1
        $x_1_3 = "c:\\Windows\\BJ.exe" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_5 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_B_2147811679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.B!MTB"
        threat_id = "2147811679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {9c 60 e8 00 00 00 00 5d b8 07 00 00 00 2b e8 8d b5 19 fe ff ff 8b 06 83 f8 00 74 11 8d b5 41 fe ff ff 8b 06 83 f8 01 0f 84 4b 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_CK_2147811826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.CK!MTB"
        threat_id = "2147811826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\rundll3222.exe" ascii //weight: 1
        $x_1_2 = "http://107.151.94.70" ascii //weight: 1
        $x_1_3 = "C:\\ProgramData\\svchost.txt" ascii //weight: 1
        $x_1_4 = "ojbkcg.exe" ascii //weight: 1
        $x_1_5 = "e:\\vs\\lujk\\Release\\lujk.pdb" ascii //weight: 1
        $x_1_6 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_7 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_CI_2147812209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.CI!MTB"
        threat_id = "2147812209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7a 41 50 63 43 ?? 4c 2f 5a 30 65 ?? 2f 42 66 62 37 41 76 43}  //weight: 1, accuracy: Low
        $x_1_2 = {30 30 4f 4f 4f 4f 4f 4f 32 66 ?? 31 2f 74 76}  //weight: 1, accuracy: Low
        $x_2_3 = "VirtualAlloc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MY_2147812290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MY!MTB"
        threat_id = "2147812290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 ca c1 e9 16 8b 04 88 84 00 89 d1 c1 ea 10 83 e2 3f 8d 84 10 00 08 04 00 89 04 24 c1 e9 0d 83 e1 07 b8 01 00 00 00 d3 e0 88 44 24 04 e8}  //weight: 1, accuracy: High
        $x_1_2 = "itoldyouso" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MZ_2147812733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MZ!MTB"
        threat_id = "2147812733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cYreenQillm" ascii //weight: 1
        $x_1_2 = ".themida" ascii //weight: 1
        $x_1_3 = ".boot" ascii //weight: 1
        $x_1_4 = "TelegramDll.dll" ascii //weight: 1
        $x_1_5 = "/dumpstatus" ascii //weight: 1
        $x_1_6 = "/checkprotection" ascii //weight: 1
        $x_1_7 = "/forcerun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MAA_2147812736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MAA!MTB"
        threat_id = "2147812736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 83 fe 01 75 02 33 f6 8a 04 39 8b d6 81 e2 ff ff 00 00 2c 7a 8a 54 54 18 32 d0 46 88 14 39 41 3b cd 7c}  //weight: 1, accuracy: High
        $x_1_2 = "GetAsyncKeyState" ascii //weight: 1
        $x_1_3 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_4 = "Process32First" ascii //weight: 1
        $x_1_5 = "[Pause Break]" ascii //weight: 1
        $x_1_6 = "[PageDown]" ascii //weight: 1
        $x_1_7 = "DllUpdate" ascii //weight: 1
        $x_1_8 = "ServiceMain" ascii //weight: 1
        $x_1_9 = "Uninstall" ascii //weight: 1
        $x_1_10 = "maindll.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_CL_2147813104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.CL!MTB"
        threat_id = "2147813104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 33 d2 8a 16 81 e1 ff 00 00 00 33 ca c1 e8 08 8b 0c 8d f8 8c 00 10 33 c1 46 4f 75 e2}  //weight: 1, accuracy: High
        $x_1_2 = {8a 19 81 e2 ff 00 00 00 33 d3 c1 e8 08 8b 14 95 f8 8c 00 10 33 c2 41 4f 75 dd}  //weight: 1, accuracy: High
        $x_1_3 = "PluginMe" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MAZ_2147813150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MAZ!MTB"
        threat_id = "2147813150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 e0 8b 0d ?? ?? ?? ?? 89 4d e4 8b 15 ?? ?? ?? ?? 89 55 e8 a1 ?? ?? ?? ?? 89 45 ec 8a 0d ?? ?? ?? ?? 88 4d f0 8d 55 e0 52 e8 ?? ?? ?? ?? 83 c4 04 50 68}  //weight: 1, accuracy: Low
        $x_1_2 = "KydhHx86c2EmIiBD" ascii //weight: 1
        $x_1_3 = "8vT2CQYLCzo-" ascii //weight: 1
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MAZ_2147813150_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MAZ!MTB"
        threat_id = "2147813150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {cf d7 b8 5e e4 d6 96 1b be 1a 0e d7 ea 78 fc 75 ca be b7 97 82 74 7f 33 c7 c7 b9 b7 82 d3 96 22}  //weight: 3, accuracy: High
        $x_3_2 = {3f 68 c9 6e 15 0e e6 5a 35 db d0 a8 78 5b 42 c3 e2 d6 3a 72 cf df 7f 5a f1 c8 30 1f a8 e4 e5 3a}  //weight: 3, accuracy: High
        $x_3_3 = "MyPlayer For My Lover" wide //weight: 3
        $x_1_4 = "@.themida" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MAC_2147813453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MAC!MTB"
        threat_id = "2147813453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".vLncpy0" ascii //weight: 1
        $x_1_2 = ".vLncpy1" ascii //weight: 1
        $x_1_3 = "PathFindFileName" ascii //weight: 1
        $x_1_4 = {79 6d ee b0 b0 e8 2e 7a 9b b5 f3 32 e7 c4 2b 9c e0 85 da 87 f7 2a 71 79 eb c1 aa c5 dd 0e c9 f1 ea 14 9f 91 3c af b2 0c 8d c4 53 f9 9c ce 99 f4 0e dc 7c 22 b6 43 96 cc 48 9c 34 bd da d1 c5 4e df 43 d6 50 58 5e 25 3d 79 21 6d 55 03 68 0f a9 03 ff a9 1e c1 d7 38 fd 09 d4 6f 91 26 19 45 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MAD_2147813455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MAD!MTB"
        threat_id = "2147813455"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c ping 127.0.0.1 -n 1 && del /f/q " ascii //weight: 1
        $x_1_2 = "post.f2pool.info" ascii //weight: 1
        $x_1_3 = "Sleep" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" ascii //weight: 1
        $x_1_5 = "LoadFromMemory END---" ascii //weight: 1
        $x_1_6 = "OpenProxy" ascii //weight: 1
        $x_1_7 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_8 = "Process32First" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MAE_2147813456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MAE!MTB"
        threat_id = "2147813456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 46 24 8b 4e 08 68 68 9c 00 10 51 ff d7}  //weight: 1, accuracy: High
        $x_1_2 = {89 46 70 8b 56 08 68 3c 9b 00 10 52 ff d7 89 46 74 8b 46 08 68 30 9b 00 10 50 ff d7}  //weight: 1, accuracy: High
        $x_1_3 = "DllUpdate" ascii //weight: 1
        $x_1_4 = "ServiceMain" ascii //weight: 1
        $x_1_5 = "Uninstall" ascii //weight: 1
        $x_1_6 = "MainDll.dll" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" ascii //weight: 1
        $x_1_8 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MAF_2147813457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MAF!MTB"
        threat_id = "2147813457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b2 67 b0 65 88 54 24 1a 88 54 24 22 88 44 24 15 88 44 24 17 88 44 24 21 88 44 24 23 8d 54 24 08 8d 44 24 14 52 b1 69 50 6a 00 c6 44 24 20 53 c6 44 24 22 44}  //weight: 1, accuracy: High
        $x_1_2 = "WINDOWS\\system32\\BRemotes.exe" ascii //weight: 1
        $x_1_3 = "user.qzone.qq.com" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v BATCOM" ascii //weight: 1
        $x_1_5 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_6 = "LockServiceDatabase" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MAH_2147813458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MAH!MTB"
        threat_id = "2147813458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RECYLLE.BIN\\TorchWooc" ascii //weight: 1
        $x_1_2 = "Sleep" ascii //weight: 1
        $x_1_3 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_4 = "KeyFilepath" ascii //weight: 1
        $x_1_5 = "ChromeSecsv7%d7.exe" ascii //weight: 1
        $x_1_6 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_7 = "Process32First" ascii //weight: 1
        $x_1_8 = "UnhookWindowsHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MAI_2147813792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MAI!MTB"
        threat_id = "2147813792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 ec 89 65 f0 33 ff 50 c7 45 ec 02 00 00 80 8b 4d ec 6a 01 57 68 ?? ?? ?? ?? 51 89 7d e0 89 7d c8 89 7d e4 89 7d e8 89 7d fc ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {81 ec 08 01 00 00 8b 8c 24 0c 01 00 00 56 57 8d 44 24 0c 68 04 01 00 00 50 51 c7 44 24 14 00 00 00 00 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 03 6a 00 6a 01 8d 54 24 20 68 00 00 00 80 52 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" ascii //weight: 1
        $x_1_4 = "Gh0st Update" ascii //weight: 1
        $x_1_5 = "ResumeThread" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $x_1_7 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_8 = "keybd_event" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MAJ_2147813793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MAJ!MTB"
        threat_id = "2147813793"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 04 53 56 6a 00 6a 00 6a 02 6a 00 6a 01 68 00 00 00 40 50 32 db ff 15}  //weight: 1, accuracy: High
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "Program Files\\Common Files\\scvhost.exe" ascii //weight: 1
        $x_1_4 = "cmd /C  regedit /s Uac.reg" ascii //weight: 1
        $x_1_5 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_6 = "Process32First" ascii //weight: 1
        $x_1_7 = "GetKeyState" ascii //weight: 1
        $x_1_8 = "[Pause Break]" ascii //weight: 1
        $x_1_9 = "[BACKSPACE]" ascii //weight: 1
        $x_1_10 = "[INSERT]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MAL_2147813794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MAL!MTB"
        threat_id = "2147813794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CcMainDll.dll" ascii //weight: 1
        $x_1_2 = "FirstRun" ascii //weight: 1
        $x_1_3 = "MainRun" ascii //weight: 1
        $x_1_4 = "ServiceMain" ascii //weight: 1
        $x_1_5 = "TestFun" ascii //weight: 1
        $x_1_6 = "Sleep" ascii //weight: 1
        $x_1_7 = "CcRmt Update" ascii //weight: 1
        $x_1_8 = "No Access" ascii //weight: 1
        $x_1_9 = "ResumeThread" ascii //weight: 1
        $x_1_10 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_CM_2147813930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.CM!MTB"
        threat_id = "2147813930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 c2 8b 55 ?? 02 c8 8b 45 ?? 32 d9 00 18}  //weight: 1, accuracy: Low
        $x_1_2 = {32 c2 02 c8 8b 45 ?? 32 d9 00 1c 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RPM_2147814100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RPM!MTB"
        threat_id = "2147814100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.php" ascii //weight: 1
        $x_1_2 = "bXN2Y3J0LmRsbA" ascii //weight: 1
        $x_1_3 = "d3RzYXBpMzIuZGxs" ascii //weight: 1
        $x_1_4 = "aW1tMzIuZGxs" ascii //weight: 1
        $x_1_5 = "d3MyXzMyLmRsbA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_CO_2147814341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.CO!MTB"
        threat_id = "2147814341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {03 ca 33 c1 8b 4d 08 03 4d fc 0f b6 09 2b c8 89 4d dc 8b 45 08 03 45 fc 8a 4d dc 88 08 0f b6 45 dc 89 45 f8 eb 8a}  //weight: 5, accuracy: High
        $x_5_2 = {c6 45 e4 56 c6 45 e5 69 c6 45 e6 72 c6 45 e7 74 c6 45 e8 75 c6 45 e9 61 c6 45 ea 6c c6 45 eb 50 c6 45 ec 72 c6 45 ed 6f c6 45 ee 74 c6 45 ef 65 c6 45 f0 63 c6 45 f1 74}  //weight: 5, accuracy: High
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Farfli_AK_2147814642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AK!MTB"
        threat_id = "2147814642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 ab 3b 5e ad 43 8e 19 89 e8 1b be 88 12 80 e7 12 e3 ee 7b eb}  //weight: 1, accuracy: High
        $x_1_2 = "%s.exe" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AL_2147815297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AL!MTB"
        threat_id = "2147815297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b1 1e 50 58 80 34 11 2d e2 fa}  //weight: 2, accuracy: High
        $x_2_2 = "ServiceMain" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AM_2147815301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AM!MTB"
        threat_id = "2147815301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 08 32 ca 02 ca 88 08 40 4e 75 f4}  //weight: 2, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MAM_2147815334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MAM!MTB"
        threat_id = "2147815334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Num Lock]" ascii //weight: 1
        $x_1_2 = "[Del]" ascii //weight: 1
        $x_1_3 = "[TAB]" ascii //weight: 1
        $x_1_4 = "termsrvhack.dll" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_6 = "taskkill /f /im cmd.exe" ascii //weight: 1
        $x_1_7 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_8 = "GetAsyncKeyState" ascii //weight: 1
        $x_1_9 = ".rotext" ascii //weight: 1
        $x_1_10 = ".rodata" ascii //weight: 1
        $x_1_11 = "Yow! Bad host lookup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AO_2147815824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AO!MTB"
        threat_id = "2147815824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aHR0cDovLzEyNC4xNTYuMTQ4LjcyOjg3ODkvdHNldHVwLjIuNC43LmV4ZQ" ascii //weight: 1
        $x_1_2 = "C:/Users/Public/Documents/Powermonster.exe" ascii //weight: 1
        $x_1_3 = "C:/Users/Public/Documents/unzip.exe" ascii //weight: 1
        $x_1_4 = "benson.pdb" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_6 = "VirtualAlloc" ascii //weight: 1
        $x_1_7 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AR_2147815913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AR!MTB"
        threat_id = "2147815913"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 11 32 54 45 e8 8b 45 08 03 45 d8 88 10 66 8b 4d e0 66 83 c1 01 66 89 4d e0 eb a9}  //weight: 2, accuracy: High
        $x_2_2 = "C:\\input.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AU_2147816086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AU!MTB"
        threat_id = "2147816086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 1f 9c 32 55 a4 42 31 b7 [0-4] 77 f6}  //weight: 2, accuracy: Low
        $x_2_2 = {49 28 db 31 67 f4 6a 0d fc 09 3f}  //weight: 2, accuracy: High
        $x_1_3 = "%s.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AV_2147816087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AV!MTB"
        threat_id = "2147816087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 c9 8a 1c 38 8b d1 81 e2 ff ff 00 00 8a 54 54 0c 32 da 41 88 1c 38 40 3b c6 72 de}  //weight: 2, accuracy: High
        $x_2_2 = {33 f6 8a 04 39 8b d6 81 e2 ff ff 00 00 2c 7a 8a 54 54 18 32 d0 46 88 14 39 41 3b cd 7c dc}  //weight: 2, accuracy: High
        $x_1_3 = "VirtualBox" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "%s\\%s.exe" ascii //weight: 1
        $x_1_6 = "ServiceMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Farfli_AP_2147816191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AP!MTB"
        threat_id = "2147816191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 08 32 4d ec 8b 55 08 88 0a 8b 45 08 8a 08 02 4d ec 8b 55 08 88 0a 8b 45 08 83 c0 01 89 45 08}  //weight: 2, accuracy: High
        $x_1_2 = "www.xy999.com" ascii //weight: 1
        $x_1_3 = "fuckyou" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_QT_2147816257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.QT!MTB"
        threat_id = "2147816257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {46 80 c2 4f 30 14 39 f7 e1 c1 ea ?? 8d 14 92 8b c1 2b c2 75 02 33 f6 41 3b 4d 0c 7c cf}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_DA_2147816262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DA!MTB"
        threat_id = "2147816262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b9 01 00 00 00 66 3b cb 75 02 33 db 80 04 3e 86 6a 00 ff d5 6a 00 ff d5 6a 00 ff d5 0f b7 d3 8a 44 54 14 30 04 3e 46 43 3b 74 24 10 7c d2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_DA_2147816262_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DA!MTB"
        threat_id = "2147816262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 4c 24 74 8a 14 08 80 f2 62 88 14 08 40 3b c5 72}  //weight: 4, accuracy: High
        $x_1_2 = "360\\360Safe\\SB360.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MAQ_2147816489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MAQ!MTB"
        threat_id = "2147816489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c4 08 8d 45 fc 50 68 3f 00 0f 00 6a 00 8d 8d f8 fe ff ff 51 68 02 00 00 80 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 08 8a 08 32 4d ec 8b 55 08 88 0a 8b 45 08 8a 08 02 4d ec 8b 55 08 88 0a b8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AQ_2147816558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AQ!MTB"
        threat_id = "2147816558"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2c df 34 75 f8 6e 09 f8 0c 0e 9c 32 55 a4 4c 7a ef}  //weight: 2, accuracy: High
        $x_2_2 = {23 de 30 0a 8d 1d [0-4] fb 6b 0e ?? 19 e1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_F_2147816643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.F!MTB"
        threat_id = "2147816643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "baidu.com" ascii //weight: 1
        $x_1_2 = "Sbrjar Kbskb" ascii //weight: 1
        $x_1_3 = "HippoPzi" ascii //weight: 1
        $x_1_4 = "Jbrja.exe" ascii //weight: 1
        $x_1_5 = "tatusbar.bmp" ascii //weight: 1
        $x_1_6 = "VirtualProtect" ascii //weight: 1
        $x_1_7 = "LoadResource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AT_2147816816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AT!MTB"
        threat_id = "2147816816"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.xy999.com" ascii //weight: 1
        $x_1_2 = "www.appspeed.com" ascii //weight: 1
        $x_1_3 = "AADz6AABBY/zxuDQzOXS4daPANLh5cbQ0q8" ascii //weight: 1
        $x_1_4 = "89LVzuLL468" ascii //weight: 1
        $x_1_5 = "kuge3907@sina.com" ascii //weight: 1
        $x_1_6 = "VirtualAlloc" ascii //weight: 1
        $x_1_7 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AD_2147817120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AD!MTB"
        threat_id = "2147817120"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PeCancer2009" ascii //weight: 1
        $x_1_2 = "C:\\myself.dll" ascii //weight: 1
        $x_1_3 = "gethostbyname" ascii //weight: 1
        $x_1_4 = "GetSystemFirmwareTable" ascii //weight: 1
        $x_1_5 = "Control_RunDLLW" ascii //weight: 1
        $x_1_6 = "HlMain.dll" ascii //weight: 1
        $x_1_7 = {62 62 62 62 62 62 62 62 62 62 00 63 63 63 63 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AX_2147819103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AX!MTB"
        threat_id = "2147819103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 c9 0f b7 d1 8a 54 55 e8 30 14 07 40 41 3b c6 72 e8}  //weight: 2, accuracy: High
        $x_1_2 = {33 d9 03 d3 8b 5d 10 8b ce 83 e1 03 33 4d f8 8b 1c 8b 0f b6 4c 3e ff 33 d9 03 d8 0f b6 04 3e 33 d3 2b c2 4e 88 44 3e 01 0f b6 c0 75 b5}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 08 8a 10 8a 4d ef 32 d1 02 d1 88 10 40 89 45 08}  //weight: 1, accuracy: High
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AY_2147819131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AY!MTB"
        threat_id = "2147819131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 08 8d 0c 02 0f b7 c6 8a 44 45 ec 30 01 46 42 3b d7 72 e3}  //weight: 2, accuracy: High
        $x_2_2 = "VirtualAlloc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AZ_2147819390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AZ!MTB"
        threat_id = "2147819390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 08 33 ca 8b 55 08 03 55 f4 88 0a 66 8b 45 fc 66 83 c0 01 66 89 45 fc eb b3}  //weight: 2, accuracy: High
        $x_2_2 = "VirtualAlloc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BA_2147821729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BA!MTB"
        threat_id = "2147821729"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 51 8b 1b 8b 03 83 c3 04 89 07 83 c7 04 53 8b 1b 81 c3 08 00 00 00 b9 00 01 00 00 8b f3 f3 a4 5b 83 c3 04 59 5b 83 c3 04 49 0f}  //weight: 1, accuracy: High
        $x_1_2 = "sjaklej4ijalkbnlksjlksjkg.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BB_2147822929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BB!MTB"
        threat_id = "2147822929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 11 8b 5c 24 58 4d 88 14 1f 47 41 88 54 24 48 89 7c 24 10 85 ed 0f 84}  //weight: 1, accuracy: High
        $x_1_2 = {50 8b c3 8b c3 58 83 ea 01 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BC_2147823212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BC!MTB"
        threat_id = "2147823212"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 10 80 f2 15 80 c2 15 88 10 40 83 ee 01 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BD_2147823633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BD!MTB"
        threat_id = "2147823633"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fuck007fuckme" ascii //weight: 1
        $x_1_2 = "[Num Lock]" ascii //weight: 1
        $x_1_3 = "[Scroll Lock]" ascii //weight: 1
        $x_1_4 = "lld.23ipavda" ascii //weight: 1
        $x_1_5 = "[Print Screen]" ascii //weight: 1
        $x_1_6 = "yuancheng" ascii //weight: 1
        $x_1_7 = "Wang" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BJ_2147826859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BJ!MTB"
        threat_id = "2147826859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b cb 2b cf 8a 14 01 80 f2 62 88 10 40 4e 75}  //weight: 1, accuracy: High
        $x_1_2 = {8a 14 01 80 f2 19 80 c2 46 88 14 01 41 3b ce 7c}  //weight: 1, accuracy: High
        $x_1_3 = "Program Files\\Common Files\\scvh0st.exe" ascii //weight: 1
        $x_1_4 = "fuckyou" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BL_2147827262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BL!MTB"
        threat_id = "2147827262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 55 e8 b1 cc 03 d0 2a c8 40 32 0a 88 0c 13 83 f8 05 76}  //weight: 1, accuracy: High
        $x_1_2 = "ServiceMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BM_2147827282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BM!MTB"
        threat_id = "2147827282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 83 c0 01 89 45 f8 8b 4d f8 3b 4d 0c 73 29 8b 55 08 03 55 f8 33 c0 8a 02 8b 4d fc 33 c8 81 e1 ff 00 00 00 8b 55 fc c1 ea 08 8b 04 8d [0-4] 33 c2 89 45 fc eb}  //weight: 1, accuracy: Low
        $x_1_2 = "admind.f3322.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BK_2147827616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BK!MTB"
        threat_id = "2147827616"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\%s.exe" ascii //weight: 1
        $x_1_2 = "ekimhuqcroanflvzgdjtxypswb" ascii //weight: 1
        $x_1_3 = "cmd.exe /c ping 127.0.0.1" ascii //weight: 1
        $x_1_4 = "LoadResource" ascii //weight: 1
        $x_1_5 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BN_2147827672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BN!MTB"
        threat_id = "2147827672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b cb 2b cf 8a 14 01 80 f2 62 88 10 40 4e 75}  //weight: 1, accuracy: High
        $x_1_2 = "fuckyou" ascii //weight: 1
        $x_1_3 = "www.jinjin.com" ascii //weight: 1
        $x_1_4 = "[Print Screen]" ascii //weight: 1
        $x_1_5 = "[Scroll Lock]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BO_2147827777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BO!MTB"
        threat_id = "2147827777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b cb 2b cf 8a 14 01 80 f2 62 88 10 40 4e 75}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\Program Files\\Common Files\\scvh0st.exe" ascii //weight: 1
        $x_1_3 = "[Scroll Lock]" ascii //weight: 1
        $x_1_4 = "[Print Screen]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RPW_2147828539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RPW!MTB"
        threat_id = "2147828539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 8a 1e 8b d0 81 e2 ff ff 00 00 8a 54 54 0c 32 d1 32 d3 40 f6 d2 88 16 41 46 66 3b cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BP_2147828568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BP!MTB"
        threat_id = "2147828568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 14 01 80 ea 76 80 f2 23 88 14 01 41 3b ce 7c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BQ_2147828574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BQ!MTB"
        threat_id = "2147828574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 55 fc 8a 1c 11 80 f3 36 88 1c 11 8b 55 fc 8a 1c 11 80 c3 12 88 1c 11 8b 55 fc 8a 1c 11 80 c3 bc 88 1c 11 8b 55 fc 8a 1c 11 80 f3 18 88 1c 11 41 3b c8 7c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BS_2147828691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BS!MTB"
        threat_id = "2147828691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 44 24 08 8a ca 03 c6 32 08 02 ca 46 3b 74 24 0c 88 08 7c}  //weight: 2, accuracy: High
        $x_2_2 = "cracked by ximo" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BT_2147828973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BT!MTB"
        threat_id = "2147828973"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 14 01 80 f2 19 80 c2 46 88 14 01 41 3b ce 7c}  //weight: 2, accuracy: High
        $x_2_2 = {8a 14 01 80 ea 46 80 f2 19 88 14 01 41 3b ce 7c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BU_2147829178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BU!MTB"
        threat_id = "2147829178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8a 14 01 80 f2 20 80 c2 7b 88 14 01 41 3b ce 7c}  //weight: 4, accuracy: High
        $x_1_2 = "PluginMe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BV_2147829295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BV!MTB"
        threat_id = "2147829295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 0c 38 80 f1 19 80 c1 7a 88 0c 38 40 3b c6 7c}  //weight: 2, accuracy: High
        $x_1_2 = "[Execute]" ascii //weight: 1
        $x_1_3 = "Let me exit" ascii //weight: 1
        $x_1_4 = "Connect OK!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BW_2147829562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BW!MTB"
        threat_id = "2147829562"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 5c 24 3c 89 5c 24 44 c6 44 24 20 4d c6 44 24 21 6f c6 44 24 22 7a 88 54 24 23 88 4c 24 26 c6 44 24 27 2f c6 44 24 28 34 c6 44 24 29 2e c6 44 24 2a 30 c6 44 24 2b 20 c6 44 24 2c 28 c6 44 24 2d 63 c6 44 24 2e 6f c6 44 24 2f 6d c6 44 24 30 70 88 4c 24 31 c6 44 24 32 74 88 54 24 33 c6 44 24 34 62 c6 44 24 36 65 c6 44 24 37 29 88 5c 24 38 ff 15}  //weight: 2, accuracy: High
        $x_1_2 = "C:\\ProgramData\\1.txt" ascii //weight: 1
        $x_1_3 = "103.59.103.16/SHELL.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BX_2147829563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BX!MTB"
        threat_id = "2147829563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "s\\dllcache\\sethc.exe" ascii //weight: 1
        $x_1_2 = "[Execute]" ascii //weight: 1
        $x_1_3 = "s\\dllcache\\osk.exe" ascii //weight: 1
        $x_1_4 = "s\\dllcache\\magnify.exe" ascii //weight: 1
        $x_1_5 = "Game Over Good Luck By Wind" ascii //weight: 1
        $x_1_6 = "SystemRoot%\\system32\\termsrvhack.dll" ascii //weight: 1
        $x_1_7 = "[Snapshot]" ascii //weight: 1
        $x_1_8 = "[Backspace]" ascii //weight: 1
        $x_1_9 = "Program Files\\Ru%d.EXE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BY_2147829918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BY!MTB"
        threat_id = "2147829918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f7 f9 8b 45 ec 2a d0 88 14 38 40 3b 45 fc 89 45 ec 72}  //weight: 2, accuracy: High
        $x_1_2 = "cmd.exe /c ping 127.0.0.1 -n 2&%s" ascii //weight: 1
        $x_1_3 = "%s\\%s.exe" ascii //weight: 1
        $x_1_4 = "[:print:]" ascii //weight: 1
        $x_1_5 = "vmp0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_DB_2147830715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DB!MTB"
        threat_id = "2147830715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8a 90 58 60 40 00 32 d1 88 90 58 60 40 00 40 3d d3 e0 00 00 7c}  //weight: 3, accuracy: High
        $x_1_2 = "vbcfg.ini" wide //weight: 1
        $x_1_3 = "C:\\1.jpg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BZ_2147830839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BZ!MTB"
        threat_id = "2147830839"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 44 24 20 8a 14 29 02 c3 2a d0 88 14 29 41 3b ce 7c}  //weight: 2, accuracy: High
        $x_1_2 = "c:\\%s.exe" ascii //weight: 1
        $x_1_3 = "cmd.exe /c ping 127.0.0.1 -n 2&%s" ascii //weight: 1
        $x_1_4 = "c:\\wiseman.exe" ascii //weight: 1
        $x_1_5 = "ekimhuqcroanflvzgdjtxypswb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_DC_2147830942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DC!MTB"
        threat_id = "2147830942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8a 0c 18 80 e9 17 80 f1 3e 80 c1 17 88 0c 18 40 3b 45 0c 7c}  //weight: 3, accuracy: High
        $x_1_2 = "www.testzake.com" ascii //weight: 1
        $x_1_3 = "C:\\TEMP\\syslog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RPT_2147832127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RPT!MTB"
        threat_id = "2147832127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 0c 06 8b 44 24 1c 0f be 04 07 99 f7 fb 8b c6 80 c2 4f 30 11 59 99 f7 f9 47 85 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RPT_2147832127_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RPT!MTB"
        threat_id = "2147832127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 8c 55 f4 fd ff ff 83 f9 3b 74 08 83 f9 64 74 03 83 f1 1b 66 89 8c 55 ec fb ff ff 42 3b d0 7c de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AAD_2147833807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AAD!MTB"
        threat_id = "2147833807"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 04 3a 34 30 2c 49 88 04 3a 42 3b d3 7c f1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MAV_2147835155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MAV!MTB"
        threat_id = "2147835155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "UkRZXBRaFV9WWys=" ascii //weight: 5
        $x_5_2 = "\\A2\\Release\\A2.pdb" ascii //weight: 5
        $x_5_3 = "SHELLCODE" ascii //weight: 5
        $x_5_4 = "C://ProgramData//zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" ascii //weight: 5
        $x_1_5 = "QueryPerformanceCounter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MAU_2147835822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MAU!MTB"
        threat_id = "2147835822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {56 8b 74 24 0c c1 ee 03 f6 44 24 0c 07 74 01 46 85 f6 74 1e 57 8b 7c 24 0c 68 00 40 00 10 57 6a 20 e8 12 00 00 00 83 c4 0c 83 c7 08 83 ee 01 75 e8 5f 8b 44 24 08 5e c3 8b 54 24 08 53 8b 5c 24 08 55 56 8b 32 69 eb b9 79 37 9e 57 8b 7a 04 85}  //weight: 10, accuracy: High
        $x_1_2 = "mod_s0beit.dll" ascii //weight: 1
        $x_1_3 = "_TwMouseWheel@4" ascii //weight: 1
        $x_1_4 = "_TwDeleteBar@4" ascii //weight: 1
        $x_1_5 = "QueryPerformanceCounter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MAS_2147836277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MAS!MTB"
        threat_id = "2147836277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f a2 8a da f6 d7 66 87 7c 24 03 8d 58 65 8d 64 24 08 eb ?? f8 66 89 5c 24 27 eb}  //weight: 5, accuracy: Low
        $x_5_2 = {91 2b db cc 5c 5c 9c 8a c7 07 02 ?? ?? ?? ?? ?? 00 00 00 8f ?? ?? ?? ?? cc ab 66 e1 2f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MAT_2147836278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MAT!MTB"
        threat_id = "2147836278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {e8 47 3c ad ff 74 24 02 eb 24 88 2b 42 fd ff 74 24 04 8d 64 24 08 66 50 ff 74 24 03 8d 64 24 02 89 4c 24 20 eb 14 cc 5f a6 d1 10 91 cb b3 79 de}  //weight: 10, accuracy: High
        $x_5_2 = ".sedata" ascii //weight: 5
        $x_1_3 = "NtQueryInformationThread" ascii //weight: 1
        $x_1_4 = "IsWow64Process" ascii //weight: 1
        $x_1_5 = "SEGetLicenseUserInfoW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MAW_2147836529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MAW!MTB"
        threat_id = "2147836529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f2 6a f8 9f 6a dd 0b 83 ?? ?? ?? ?? 64 24 01 89 44 24 02 0f 95 c4 66 8b c2 eb ?? f6 da 0f 31}  //weight: 1, accuracy: Low
        $x_1_2 = {67 fc 92 f5 04 ad 49 66 8b c2 f6 dc 3a e5 66 0f bb d8 52 66 0f a3 e0 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MAX_2147836996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MAX!MTB"
        threat_id = "2147836996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cYreenQilln97vqz" ascii //weight: 10
        $x_10_2 = {90 32 65 90 df 04 7c 5d 5b 0b 5e 78 db 21 a9 4a 24 78 23 23 76 2d 41 66 5f 76 65 58 71 42 ca 1e}  //weight: 10, accuracy: High
        $x_1_3 = ".vmps0" ascii //weight: 1
        $x_1_4 = ".vmps1" ascii //weight: 1
        $x_1_5 = "QueryFullProcessImageNameW" ascii //weight: 1
        $x_1_6 = "WTSSendMessageW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MAY_2147837861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MAY!MTB"
        threat_id = "2147837861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cYreenQilln97vqz" ascii //weight: 10
        $x_10_2 = {13 28 81 3e bd 25 56 52 f8 27 42 42 c3 35 b7 06 e3 7f f1 15 38 13 4f 6b de 09 23 6b 03 46 ea 39}  //weight: 10, accuracy: High
        $x_1_3 = ".vmps0" ascii //weight: 1
        $x_1_4 = ".vmps1" ascii //weight: 1
        $x_1_5 = "QueryFullProcessImageNameW" ascii //weight: 1
        $x_1_6 = "WTSSendMessageW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_CZ_2147838504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.CZ!MTB"
        threat_id = "2147838504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 55 fc 81 e2 ?? ?? ?? ?? 8b 45 08 03 45 e0 8a 08 32 4c 55 ec 8b 55 08 03 55 e0 88 0a 66 8b 45 fc 66 05 01 00 66 89 45 fc eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MAR_2147840322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MAR!MTB"
        threat_id = "2147840322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "InitEngine" ascii //weight: 5
        $x_1_2 = {0f ac da 11 ff 34 24 f6 d8 66 d3 d2 66 0f be d1 f8 5a c0 c0 06 68 ?? ?? ?? ?? 30 c3 80 ca 4f 66 0f bd d0 0f b6 c0 66 f7 c2 40 2b 83 c4 08 0f 87}  //weight: 1, accuracy: Low
        $x_1_3 = {83 ed 04 88 2c 24 89 45 00 c6 04 24 7e 88 0c 24 9c 8d 64 24 24 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_EC_2147842699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.EC!MTB"
        threat_id = "2147842699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@shift /0" ascii //weight: 1
        $x_1_2 = "&@cls&@set" ascii //weight: 1
        $x_1_3 = "=1pLdsWGj3c4rqJ2Kt76aihTZRloUYBMbmwk" ascii //weight: 1
        $x_1_4 = "QHI90SPveC85zAfgyEODuFN@VnxX" ascii //weight: 1
        $x_1_5 = "inicio" ascii //weight: 1
        $x_1_6 = "descpu" ascii //weight: 1
        $x_1_7 = "opcpu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_EC_2147842699_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.EC!MTB"
        threat_id = "2147842699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Melody.dat" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = "EnumProcessModules" ascii //weight: 1
        $x_1_4 = "waveInStart" ascii //weight: 1
        $x_1_5 = "ShellExecuteExA" ascii //weight: 1
        $x_1_6 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_7 = "DefWindowProcA" ascii //weight: 1
        $x_1_8 = "Client hook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MF_2147843132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MF!MTB"
        threat_id = "2147843132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {50 72 6f 67 72 61 6d 44 61 74 61 2f 2f 48 00 00 aa aa aa aa 46 42 73 61 46 52 51 55 48 68 55 55 47 68 77 56 46 43 4d 72}  //weight: 2, accuracy: High
        $x_2_2 = "AA1\\Release\\AA1.pdb" ascii //weight: 2
        $x_2_3 = "https://note.youdao.com/yws/public/resource/d443b2f84ff00a25620bd5562b07a800/xmlnote" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_EM_2147843920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.EM!MTB"
        threat_id = "2147843920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_setmbcp" ascii //weight: 1
        $x_1_2 = "programB.exe" ascii //weight: 1
        $x_1_3 = "Ch7Demo6.EXE" wide //weight: 1
        $x_1_4 = "CreateThread" ascii //weight: 1
        $x_1_5 = "47.242.89.34" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_EM_2147843920_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.EM!MTB"
        threat_id = "2147843920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "F-PROT.exe" ascii //weight: 1
        $x_1_2 = "avgaurd.exe" ascii //weight: 1
        $x_1_3 = "spidernt.exe" ascii //weight: 1
        $x_1_4 = "TrojanHunter.exe" ascii //weight: 1
        $x_1_5 = "QUHLPSVC.EXE" ascii //weight: 1
        $x_1_6 = "[CLEAR]" ascii //weight: 1
        $x_1_7 = "[BACKSPACE]" ascii //weight: 1
        $x_1_8 = "[DELETE]" ascii //weight: 1
        $x_1_9 = "[INSERT]" ascii //weight: 1
        $x_1_10 = "[Num Lock]" ascii //weight: 1
        $x_1_11 = "[Down]" ascii //weight: 1
        $x_1_12 = "[Right]" ascii //weight: 1
        $x_1_13 = "[Left]" ascii //weight: 1
        $x_1_14 = "www.jinjin.com" ascii //weight: 1
        $x_1_15 = "FUCK YOU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MG_2147843954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MG!MTB"
        threat_id = "2147843954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "CppBackdoor\\Loader\\Release\\Loader.pdb" ascii //weight: 5
        $x_5_2 = {51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 01 14 51 51 1d 50 55 51 9b b6 ab 32 51 51 51 51 51 51}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BAJ_2147843963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BAJ!MTB"
        threat_id = "2147843963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "F-PROT.exe" ascii //weight: 1
        $x_1_2 = "avgaurd.exe" ascii //weight: 1
        $x_1_3 = "spidernt.exe" ascii //weight: 1
        $x_1_4 = "TrojanHunter.exe" ascii //weight: 1
        $x_1_5 = "QUHLPSVC.EXE" ascii //weight: 1
        $x_1_6 = "[CLEAR]" ascii //weight: 1
        $x_1_7 = "[BACKSPACE]" ascii //weight: 1
        $x_1_8 = "[DELETE]" ascii //weight: 1
        $x_1_9 = "[INSERT]" ascii //weight: 1
        $x_1_10 = "[Num Lock]" ascii //weight: 1
        $x_1_11 = "[Down]" ascii //weight: 1
        $x_1_12 = "[Right]" ascii //weight: 1
        $x_1_13 = "[Left]" ascii //weight: 1
        $x_1_14 = "ewteam.e2.luyouxia.net" ascii //weight: 1
        $x_1_15 = "fuckyou" ascii //weight: 1
        $x_1_16 = "guduo.xyz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (15 of ($x*))
}

rule Trojan_Win32_Farfli_BAK_2147843964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BAK!MTB"
        threat_id = "2147843964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 14 01 80 ea 51 80 f2 29 88 14 01 41 3b ce 7c}  //weight: 2, accuracy: High
        $x_2_2 = {8a 14 01 80 f2 29 80 c2 51 88 14 01 41 3b ce 7c}  //weight: 2, accuracy: High
        $x_1_3 = "[CLEAR]" ascii //weight: 1
        $x_1_4 = "[BACKSPACE]" ascii //weight: 1
        $x_1_5 = "[DELETE]" ascii //weight: 1
        $x_1_6 = "[INSERT]" ascii //weight: 1
        $x_1_7 = "[Num Lock]" ascii //weight: 1
        $x_1_8 = "FUCK YOU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BAL_2147844298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BAL!MTB"
        threat_id = "2147844298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {6a 00 ff d7 30 1e 6a 00 ff d7 00 1e 6a 00 ff d7 83 c6 01 83 ed 01 75}  //weight: 4, accuracy: High
        $x_1_2 = "115.28.72.212:5760/850lobby.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RPQ_2147844744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RPQ!MTB"
        threat_id = "2147844744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "batiya.exe" ascii //weight: 1
        $x_1_2 = "ProgramData\\homo\\2.exe" ascii //weight: 1
        $x_1_3 = "154.39.239.202" ascii //weight: 1
        $x_1_4 = "tock.exe" ascii //weight: 1
        $x_1_5 = "test.exe" ascii //weight: 1
        $x_1_6 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_7 = "ShellExecuteA" ascii //weight: 1
        $x_1_8 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BAM_2147844813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BAM!MTB"
        threat_id = "2147844813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 04 8d 84 24 34 01 00 00 50 8b 84 24 38 02 00 00 83 c0 08 50 ff b4 24 40 01 00 00 ff 15 [0-4] 8b 44 24 58 03 84 24 2c 01 00 00 89 84 24 38 02 00 00 8d 84 24 88 01 00 00 50 ff b4 24 38 01 00 00 ff 15 [0-4] ff b4 24 34 01 00 00 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {2b f2 8b f8 8a 04 39 8d 49 01 34 51 88 41 ff 83 ee 01 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BAN_2147844941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BAN!MTB"
        threat_id = "2147844941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\Public\\565.zip" ascii //weight: 1
        $x_1_2 = "123.55.89.88" ascii //weight: 1
        $x_1_3 = "C:\\Users\\Public\\555.zip" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Plus!\\Themes\\Current" ascii //weight: 1
        $x_1_5 = "tg://setlanguage?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BAO_2147845021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BAO!MTB"
        threat_id = "2147845021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "imgcache.vip033324.xyz" ascii //weight: 1
        $x_1_2 = "87.251.txt" ascii //weight: 1
        $x_1_3 = "pdate360.dat" ascii //weight: 1
        $x_1_4 = "C:\\ProgramData\\ThunderUpdate" ascii //weight: 1
        $x_1_5 = {83 c4 08 6a 05 68 b4 51 40 00 68 0c 54 40 00 68 e8 51 40 00 68 ac 51 40 00 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RPX_2147845326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RPX!MTB"
        threat_id = "2147845326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 c9 01 ff 8d 14 02 8b 12 81 e2 ff 00 00 00 81 c0 01 00 00 00 09 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RPX_2147845326_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RPX!MTB"
        threat_id = "2147845326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 33 81 ea 01 00 00 00 bf ?? ?? ?? ?? 43 29 ff 4f 39 c3 75 d5 01 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RPX_2147845326_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RPX!MTB"
        threat_id = "2147845326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5a 57 5b 01 fb e8 ?? 00 00 00 81 ef 01 00 00 00 21 df 31 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RPX_2147845326_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RPX!MTB"
        threat_id = "2147845326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f8 83 c0 01 89 45 f8 8b 4d ff 81 e1 ff 00 00 00 8b 55 fe 81 e2 ff 00 00 00 0b ca 85 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RPX_2147845326_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RPX!MTB"
        threat_id = "2147845326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d8 89 5c 24 50 85 db 74 78 33 c0 80 34 30 63 40 3d 8c 03 00 00 72 f4 8d 44 24 14 50 6a 00 6a 00 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RPX_2147845326_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RPX!MTB"
        threat_id = "2147845326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 53 53 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b f0 5f 85 f6 75 04 5e 5b 59 c3}  //weight: 1, accuracy: Low
        $x_1_2 = "hdietrich2@hotmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RPX_2147845326_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RPX!MTB"
        threat_id = "2147845326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 2c 4b c6 44 24 2e 52 c6 44 24 2f 4e c6 44 24 31 4c c6 44 24 32 33 c6 44 24 33 32 c6 44 24 34 2e c6 44 24 35 64 c6 44 24 38 00 c6 44 24 1c 56 c6 44 24 1d 69 c6 44 24 1e 72 c6 44 24 1f 74 c6 44 24 20 75 c6 44 24 21 61 c6 44 24 23 41 c6 44 24 26 6f c6 44 24 27 63 c6 44 24 28 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BAQ_2147845548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BAQ!MTB"
        threat_id = "2147845548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 55 08 03 55 fc 0f be 02 2d ce 00 00 00 8b 4d 08 03 4d fc 88 01 8b 55 08 03 55 fc 0f be 02 35 c3 00 00 00 8b 4d 08 03 4d fc 88 01 eb}  //weight: 3, accuracy: High
        $x_1_2 = "C:\\2.txt" ascii //weight: 1
        $x_1_3 = "[Insert]" ascii //weight: 1
        $x_1_4 = "[Scroll Lock]" ascii //weight: 1
        $x_1_5 = "[Print Screen]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BAP_2147845740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BAP!MTB"
        threat_id = "2147845740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 08 8a 08 32 4d 13 02 4d 13 88 08 40 89 45 08 b8 [0-4] c3 ff 45 ec c7 45 fc 01 00 00 00 eb}  //weight: 2, accuracy: Low
        $x_1_2 = "C:\\Windows\\Temp\\hankjin.temp.%d" ascii //weight: 1
        $x_1_3 = "UPJBowljoabRoDijeA" ascii //weight: 1
        $x_1_4 = "[NageBowl]" ascii //weight: 1
        $x_1_5 = "[Ilsepr]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BAR_2147846118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BAR!MTB"
        threat_id = "2147846118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {51 c6 44 24 18 57 c6 44 24 1d 45 c6 44 24 1e 54 c6 44 24 1f 2e 88 5c 24 21 88 5c 24 22 c6 44 24 23 00 c6 44 24 26 74 c6 44 24 27 65 c6 44 24 28 72 c6 44 24 2a 65 c6 44 24 2b 74 c6 44 24 2c 52 c6 44 24 2d 65 c6 44 24 2e 61 c6 44 24 30 46 c6 44 24 31 69 88 5c 24 32 c6 44 24 33 65 c6 44 24 34 00 ff 15}  //weight: 2, accuracy: High
        $x_2_2 = {50 c6 44 24 36 52 c6 44 24 37 4e c6 44 24 39 4c c6 44 24 3a 33 c6 44 24 3b 32 c6 44 24 3c 2e c6 44 24 3d 64 c6 44 24 3e 6c c6 44 24 3f 6c c6 44 24 40 00 c6 44 24 28 56 c6 44 24 29 69 c6 44 24 2a 72 88 5c 24 2b c6 44 24 2c 75 c6 44 24 2d 61 c6 44 24 2e 6c c6 44 24 2f 46 c6 44 24 30 72 c6 44 24 31 65 c6 44 24 32 65 c6 44 24 33 00 ff d6 8b 3d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BAS_2147846143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BAS!MTB"
        threat_id = "2147846143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 4d f0 83 c1 01 89 4d f0 83 7d f0 10 7d 1b 8b 55 f0 0f b6 44 15 a4 8b 4d f0 0f be 54 0d c0 33 d0 8b 45 f0 88 54 05 c0 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BAT_2147846660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BAT!MTB"
        threat_id = "2147846660"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "154.221.27.200/word.exe" wide //weight: 1
        $x_1_2 = "154.221.27.200/img.jpg" wide //weight: 1
        $x_1_3 = "154.221.27.200/service.log" wide //weight: 1
        $x_1_4 = "154.221.27.200/360.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BAV_2147847090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BAV!MTB"
        threat_id = "2147847090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 45 98 89 4d fc 56 68 [0-4] 50 ff 15 [0-4] 83 c4 10 8d 45 98 50 6a 00 6a 00 ff 15 [0-4] 8b f8 85 ff 74}  //weight: 2, accuracy: Low
        $x_2_2 = {53 55 56 57 6a 40 bf 58 db 04 00 68 00 30 00 00 33 ed 57 8b d9 55 ff 15 [0-4] 8b f0 57 56 68}  //weight: 2, accuracy: Low
        $x_1_3 = "103.100.210.9" ascii //weight: 1
        $x_1_4 = "154.211.13.11" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Farfli_BAU_2147847190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BAU!MTB"
        threat_id = "2147847190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 65 c4 00 6a 6b 53 c7 45 b4 30 00 00 00 c7 45 b8 03 00 00 00 c7 45 bc [0-4] 89 5d c8 ff d6 68 00 7f 00 00 6a 00 89 45 cc ff 15 [0-4] 6a 6c ff 75 c8 89 45 d0 c7 45 d4 06 00 00 00 c7 45 d8 6d 00 00 00 89 7d dc ff d6}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_GHJ_2147847995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.GHJ!MTB"
        threat_id = "2147847995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 e0 0f be 4c 05 f0 8b 55 e4 03 55 d8 0f b6 02 33 c1 8b 4d e4 03 4d d8 88 01 8b 45 e0 83 c0 01 89 45 e0 eb 9d}  //weight: 10, accuracy: High
        $x_1_2 = "C:\\Del.bat" ascii //weight: 1
        $x_1_3 = "\\KLSNIF.key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BAW_2147848227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BAW!MTB"
        threat_id = "2147848227"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 ec 1c 8b 49 20 55 56 8d 44 24 14 57 50 51 ff 15 [0-4] 8b 4c 24 20 b8 56 55 55 55 f7 e9 8b c2 68 [0-4] c1 e8 1f 03 d0 8b 44 24 28 8b fa 8d 4c 24 14 99 2b c2}  //weight: 3, accuracy: Low
        $x_2_2 = "cloudservicesdevc.tk/picturess/2023" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BAX_2147848228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BAX!MTB"
        threat_id = "2147848228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {89 45 fc 6a 04 68 00 10 00 00 d9 6d fc df 7d f8 8b 5d f8 c1 e3 0a 53 d9 6d 0a 6a 00 ff 15}  //weight: 3, accuracy: High
        $x_2_2 = {8b cb 2b cf 8a 14 01 80 f2 62 88 10 40 4e 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_BAY_2147848394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.BAY!MTB"
        threat_id = "2147848394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "47.243.229.22:456//fox2/shost2.exe" wide //weight: 1
        $x_1_2 = "Users\\Public\\Downloads\\jhg.exe" wide //weight: 1
        $x_1_3 = "fox2/1.vbs" wide //weight: 1
        $x_1_4 = "fox2/wd.bin" wide //weight: 1
        $x_1_5 = "Users\\Public\\Downloads\\1.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RPY_2147849503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RPY!MTB"
        threat_id = "2147849503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 8d 45 fc 50 ff 36 ff d3 3d 0d 00 00 c0 74 24 83 c6 04 83 c7 10 81 fe}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RPY_2147849503_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RPY!MTB"
        threat_id = "2147849503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 1e 29 c0 46 29 c0 47 39 ce 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RPY_2147849503_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RPY!MTB"
        threat_id = "2147849503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {29 c0 31 37 01 db 81 c7 01 00 00 00 39 d7 75 e0 21 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RPY_2147849503_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RPY!MTB"
        threat_id = "2147849503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 fe 29 ff 8d 04 02 8b 00 81 c7 01 00 00 00 81 e0 ff 00 00 00 81 c2 01 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_DAM_2147849982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DAM!MTB"
        threat_id = "2147849982"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 01 32 c2 02 c2 88 01 41 83 ee 01 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_DAM_2147849982_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DAM!MTB"
        threat_id = "2147849982"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 14 01 80 c2 66 80 f2 fe 88 14 01 41 3b ce 7c}  //weight: 2, accuracy: High
        $x_2_2 = {56 57 6a 04 68 00 10 00 00 55 6a 00 ff 15 [0-4] 8b f8 8b cb 89 7c 24 1c e8}  //weight: 2, accuracy: Low
        $x_1_3 = "[Execute]" ascii //weight: 1
        $x_1_4 = "[Backspace]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_DAN_2147850271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DAN!MTB"
        threat_id = "2147850271"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {c7 45 84 43 00 3a 00 c7 45 88 5c 00 5c 00 c7 45 8c 50 00 72 00 c7 45 90 6f 00 67 00 c7 45 94 72 00 61 00 c7 45 98 6d 00 44 00 c7 45 9c 61 00 74 00 c7 45 a0 61 00 5c 00 c7 45 a4 5c 00 56 00 c7 45 a8 69 00 64}  //weight: 4, accuracy: High
        $x_1_2 = "156.236.71.115/360.exe" wide //weight: 1
        $x_1_3 = "154.211.14.91/360.exe" wide //weight: 1
        $x_1_4 = "154.221.27.200/360.exe" wide //weight: 1
        $x_1_5 = "39.109.126.107/360.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Farfli_DAO_2147850600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DAO!MTB"
        threat_id = "2147850600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MDJlOWMxZmItYTVmMy1jODhiLTZhMmYtODNlMTAzNTNmM2E0" ascii //weight: 1
        $x_1_2 = "ZmZmODdmZTgtOGJmZi04M2YwLWM0MGMtNDY3NDY3NTY1M2U4" ascii //weight: 1
        $x_1_3 = "MDAwMDQ0MWMtNTEwMC01MDUyLTUwNTAtNTA1MDUwNTY1MGM3" ascii //weight: 1
        $x_1_4 = "ODMwMDAwN2UtMDRjNC0wMWI4LTAwMDAtMDA1ZjVlNWI4M2M0" ascii //weight: 1
        $x_1_5 = "OTA5MDkwOTAtNDQ4Yi0wNDI0LTU2OGItZjE1MGU4YTMwYTAw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_DAP_2147850618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DAP!MTB"
        threat_id = "2147850618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {50 51 c7 45 e0 43 72 65 61 c7 45 e4 74 65 45 76 c7 45 e8 65 6e 74 41 88 5d ec ff d7}  //weight: 2, accuracy: High
        $x_2_2 = {8d 45 e0 50 51 c7 45 e0 43 72 65 61 c7 45 e4 74 65 45 76 c7 45 e8 65 6e 74 41 88 5d ec ff d7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_DAQ_2147850628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DAQ!MTB"
        threat_id = "2147850628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 f0 02 4e 00 33 c9 8d 75 08 e8 ?? 0b 00 00 85 c0 7c 03 c6 07 01 68 fc 02 4e 00 33 c9 8d 75 08 e8 ?? 0b 00 00 85 c0 7c}  //weight: 2, accuracy: Low
        $x_1_2 = {45 84 50 ff 15 70 81 4d 00 85 c0 0f 84 64 01 00 00 0f b7 45 98 6a ff 50 0f b7 45 96 50 0f b7 45 94 50 0f b7 45 92 50 0f b7 45 8e 50 0f b7 45}  //weight: 1, accuracy: High
        $x_1_3 = {5b c9 c2 04 00 8d 45 e4 50 68 b4 8b 4d 00 6a 01 57 68 84 8c 4d 00 89 7d e4 ff 15 80 86 4d 00 3b c7 7d 0f 8b 45 d8 83 c0 f0 e8 74 04}  //weight: 1, accuracy: High
        $x_1_4 = "infoc0.duba.net/c" wide //weight: 1
        $x_1_5 = "Hdgtdb.exe" wide //weight: 1
        $x_1_6 = "testWrite.txt" wide //weight: 1
        $x_1_7 = "maanshan zhiye" wide //weight: 1
        $x_1_8 = "%x.exe" wide //weight: 1
        $x_1_9 = "SELECT * FROM AntiVirusProduct" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_DAR_2147851320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DAR!MTB"
        threat_id = "2147851320"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 6e 73 43 57 4d 65 49 7a 55 77 56 45 6c 45 59 4e 71 58 51 54 4d 62 67 6e 45 6f 43 48 74 75 54 4e 66 41 74 4f 55 63 61 00 6e 69 44 4a 67 64 4a 7a 46 71 4a 7a 6e 50 64 46 75 57 56}  //weight: 1, accuracy: High
        $x_1_2 = {59 6b 68 46 79 79 4e 73 4b 56 69 71 58 4f 65 63 43 6c 74 6f 58 00 4d 6e 4b 54 77 64 54 65 70 64 45 76 61 4c 74 6a 4b 4e 00 4c 45 6d 79 76 62 6d 51 50 42 58 4c 63 44 43 75 61 42 63 71 4c}  //weight: 1, accuracy: High
        $x_1_3 = {43 4d 4c 55 77 75 56 6e 62 47 77 71 4b 4b 4d 75 43 56 49 4a 71 6a 6b 45 62 4a 71 72 6d 42 5a 6c 75 42 00 43 66 4c 48 51 46 59 59 79 70 79 63 76 79 73 7a 4e 6e 50 6a 4c 6d 62 56 59 44 51 4d 68 75 65 6e 42 6a 4b 58 4a 53 6d 62}  //weight: 1, accuracy: High
        $x_1_4 = {73 7a 49 77 45 71 4d 66 42 62 61 72 50 63 66 58 53 45 45 57 53 4d 69 47 00 4c 43 66 78 4c 57 6b 4a 53 73 5a 41 67 6c 52 48 63 6b 42 64 6e 69 62 41 43 4b 67 67 43 44 4d 41 71 6e 65}  //weight: 1, accuracy: High
        $x_1_5 = "oIlmPRKVCRIqjuuTjEAvQDsRtnmYObDTCDkmpPGDtZXULdhsGBSwnRFAkNppPSNrxxczh" ascii //weight: 1
        $x_1_6 = {33 00 36 00 30 00 53 00 61 00 66 00 65 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_DAT_2147851786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DAT!MTB"
        threat_id = "2147851786"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 04 1e 99 bd 14 4e 01 00 f7 fd 8a 04 39 bd 05 00 00 00 80 ea 77 32 c2 46 88 04 39 8b c1 99 f7 fd 85 d2 75 02 33 f6 8b 44 24 18 41 3b c8 7c}  //weight: 2, accuracy: High
        $x_1_2 = {81 ec c0 09 00 00 b9 70 02 00 00 be ?? ?? ?? ?? 8b fc f3 a5 ff d0}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 04 68 00 10 00 00 8b 48 10 8b 50 0c 51 8b 4d e4 03 d1 52 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {45 e8 89 65 f0 83 38 00 75 25 8d 4d c0 68 b0 6c 40 00 51 c6 45 fc 0c c7 45 c0 42 00 00 00 e8 e9 26 00 00 b8 39 24 40 00 c3 b8 74 24 40 00 c3 b8 45 24 40 00 c3 8b 55 ec 8b 4d e8 b8 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_DAS_2147851800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DAS!MTB"
        threat_id = "2147851800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b c7 6a 03 99 59 f7 f9 83 fa 02 75 06 8a 45 f8 28 04 37 83 fa 01 75 06 8a 45 f4 28 04 37 3b d3 75 09 8a 45 f4 02 45 f8 28 04 37 47 3b 7d fc 7c}  //weight: 2, accuracy: High
        $x_2_2 = {ff d7 6a 1a 99 59 f7 f9 8b 4d 08 8a 44 15 e4 88 04 0e 46 3b f3 7c}  //weight: 2, accuracy: High
        $x_1_3 = "ekimhuqcroanflvzgdjtxypswb" ascii //weight: 1
        $x_1_4 = "cmd.exe /c ping 127.0.0.1 -n 2" ascii //weight: 1
        $x_1_5 = "c:\\%s.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_DAV_2147852484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DAV!MTB"
        threat_id = "2147852484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 80 c2 66 80 f2 fe 88 14 01 41 3b ce 7c}  //weight: 1, accuracy: High
        $x_1_2 = {8b 41 08 6a ff 50 ff 15 ?? ?? ?? ?? 68 2c 01 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {50 8d 4c 24 10 50 51 50 50 8b 86 a8 00 00 00 8d 54 24 24 6a 0c 52 68 04 00 00 98 50 c7 44 24 34 01 00 00 00 c7 44 24 38 20 bf 02 00 c7 44 24 3c 88 13 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = "PluginMe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_DAW_2147852758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DAW!MTB"
        threat_id = "2147852758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 45 ec 83 c0 01 89 45 ec 83 7d ec 04 7d 15 8b 4d f4 03 4d ec 8a 11 80 f2 36 8b 45 f4 03 45 ec 88 10 eb}  //weight: 3, accuracy: High
        $x_1_2 = "c:\\Microsoft.cjk" ascii //weight: 1
        $x_1_3 = "taskkill /IM 360tray.exe /F" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_DAX_2147888473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DAX!MTB"
        threat_id = "2147888473"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 10 6a 00 8b 56 04 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a ff 51 6a ff 52 8b f8 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8b d8 b9 00 00 04 00 b8 2a 2a 2a 2a 8b fb f3 ab 83 c4 04 bf 13 00 00 00 8d 55 f8 6a 00 52 53 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = "rossecorPlartneC\\metsyS\\NOITPIRCSED\\ERAWDRAH" ascii //weight: 1
        $x_1_4 = "opjkropioiasdjaieee" ascii //weight: 1
        $x_1_5 = "index[3].txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_DAY_2147888654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DAY!MTB"
        threat_id = "2147888654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 89 55 f8 8b 55 0c 03 55 f0 8b 45 08 03 45 f8 8a 0a 32 08 8b 55 0c 03 55 f0 88 0a e9}  //weight: 1, accuracy: High
        $x_1_2 = {40 89 45 f4 8b 55 08 03 55 f8 8a 02 88 45 fc 8b 4d 08 03 4d f8 8b 55 08 03 55 f4 8a 02 88 01 8b 4d 08 03 4d f4 8a 55 fc 88 11 eb}  //weight: 1, accuracy: High
        $x_1_3 = {55 8b ec 83 ec 0c c6 45 f4 4d c6 45 f5 61 c6 45 f6 72 c6 45 f7 6b c6 45 f8 54 c6 45 f9 69 c6 45 fa 6d c6 45 fb 65 c6 45 fc}  //weight: 1, accuracy: High
        $x_1_4 = "Cdefghij Lmnopqrst Vwxyabc Efghijkl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_GMH_2147889125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.GMH!MTB"
        threat_id = "2147889125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 83 f9 0c ?? ?? 33 c9 0f b7 d1 8a 54 55 e4 30 14 07 40 41 3b c6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ASDA_2147890340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ASDA!MTB"
        threat_id = "2147890340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 f2 c7 45 ec 47 65 74 50 c7 45 f0 72 6f 63 41 c7 45 f4 64 64 72 65 66 c7 45 f8 73 73}  //weight: 1, accuracy: High
        $x_1_2 = "sandbox" wide //weight: 1
        $x_1_3 = "virtualbox" wide //weight: 1
        $x_1_4 = "samplevm" wide //weight: 1
        $x_1_5 = "cuckoo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_GME_2147890444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.GME!MTB"
        threat_id = "2147890444"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b e8 c7 45 ?? 43 3a 2f 2f c7 45 ?? 55 73 65 72 c7 45 ?? 73 2f 2f 50 c7 45 ?? 75 62 6c 69 c7 45 ?? 63 2f 2f 44 c7 45 ?? 6f 77 6e 6c c7 45 ?? 6f 61 64 73 66 c7 45 ?? 2f 2f}  //weight: 10, accuracy: Low
        $x_1_2 = "BrowserConfigFileInfoA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_DAU_2147891266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DAU!MTB"
        threat_id = "2147891266"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 56 57 89 4d e4 89 65 f0 6a 00 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 6a 00 6a 00 68 ?? ?? 40 00 68 ?? ?? 40 00 6a 00 e8 ?? ?? ?? ?? 6a 00 6a 00 6a 00 68 ?? ?? 40 00 68 ?? ?? 40 00 6a 00 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {55 8b ec 83 ec 08 53 56 57 6a 00 6a 00 68 ?? ?? 40 00 68 ?? ?? 40 00 6a 00 e8 ?? ?? ?? ?? 6a 00 6a 00 6a 04 6a 00 6a 00 68 00 00 00 80 68 ?? ?? 40 00 ff 15}  //weight: 2, accuracy: Low
        $x_1_3 = {8b f8 6a 40 68 00 10 00 00 57 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = "C:\\ProgramData\\ProgramData.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ASDB_2147891789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ASDB!MTB"
        threat_id = "2147891789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 01 c7 45 ?? 79 6f 75 72 c7 45 ?? 46 75 6e 63 c7 45 ?? 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RG_2147891881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RG!MTB"
        threat_id = "2147891881"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 90 90 90 90 8b 55 fc 80 04 11 7a 90 90 90 90 8b 55 fc 8a 1c 11 80 f3 19 88 1c 11 41 3b c8 7c e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ASDC_2147892256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ASDC!MTB"
        threat_id = "2147892256"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 02 56 ff 15 [0-4] c7 45 bc 53 59 53 54 c7 45 c0 45 4d 5c 43 c7 45 c4 75 72 72 65 c7 45 c8 6e 74 43 6f c7 45 cc 6e 74 72 6f c7 45 d0 6c 53 65 74 c7 45 d4 5c 53 65 72 c7 45 d8 76 69 63 65 c7 45 dc 73 5c 25 73}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\Program Files\\Common Files\\scvhost.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_DAZ_2147892760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.DAZ!MTB"
        threat_id = "2147892760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 0c c7 45 a8 61 6d 20 46 c7 45 ac 69 6c 65 73 c7 45 b0 20 28 78 38 c7 45 b4 36 29 5c 4d 66 c7 45 b8 69 63 88 5d ba c7 45 bb 6f 73 6f 66}  //weight: 1, accuracy: High
        $x_1_2 = {50 c7 84 24 ?? ?? 00 00 43 3a 5c 50 c7 84 24 ?? ?? 00 00 72 6f 67 72 c7 84 24 ?? ?? 00 00 61 6d 20 46 c7 84 24 ?? ?? 00 00 69 6c 65 73 c7 84 24 ?? ?? 00 00 20 28 78 38 c7 84 24 ?? ?? 00 00 36 29 5c 4d c7 84 24 ?? ?? 00 00 69 63 72 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_NF_2147893872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.NF!MTB"
        threat_id = "2147893872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.97dmu.net" ascii //weight: 1
        $x_1_2 = "Skkojf hqaoy" ascii //weight: 1
        $x_1_3 = "Wsuwkb asbmmyry" ascii //weight: 1
        $x_1_4 = "97mu.f3322.org" ascii //weight: 1
        $x_1_5 = "Windows Omaqgk" ascii //weight: 1
        $x_1_6 = "Okbyqce.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_Z_2147894036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.Z!MTB"
        threat_id = "2147894036"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 86 0c 01 00 00 8b ce 50 e8 ?? ?? 00 00 8b 1d ?? ?? ?? ?? 8d be 0c 02 00 00 57 ff d3 6a 5c 57 ff 15 ?? ?? ?? ?? 59 89 45 f0 85 c0 59}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ASDF_2147895194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ASDF!MTB"
        threat_id = "2147895194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 c8 31 d2 f7 f6 8b 45 04 0f b6 04 10 30 04 0b 83 c1 01 39 cf 75}  //weight: 2, accuracy: High
        $x_1_2 = {83 ec 08 c7 04 24 e0 2e 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = "fuckyou" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ASDF_2147895194_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ASDF!MTB"
        threat_id = "2147895194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 10 8b f1 0f be 04 07 99 f7 7d 0c 8b 45 08 80 c2 4f 30 14 01 b8 cd cc cc cc f7 e1 41 c1 ea 02 8d 04 92 8d 57 01 33 ff 3b f0 0f 45 fa 3b cb 7c}  //weight: 1, accuracy: High
        $x_1_2 = "VGBLgtVRfwCtwdN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ASDD_2147895488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ASDD!MTB"
        threat_id = "2147895488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 55 f0 8b 55 0c 03 55 e8 8b 45 08 03 45 f0 8a 0a 32 08 8b 55 0c 03 55 e8 88 0a e9}  //weight: 1, accuracy: High
        $x_1_2 = {ff 43 c6 85 [0-2] ff ff 6f c6 85 [0-2] ff ff 6e c6 85 [0-2] ff ff 6e c6 85 [0-2] ff ff 65 c6 85 [0-2] ff ff 63 c6 85 [0-2] ff ff 74 c6 85 [0-2] ff ff 47 c6 85 [0-2] ff ff 72 c6 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ASDE_2147895489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ASDE!MTB"
        threat_id = "2147895489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d ec 8a 1c 08 80 c3 ?? 88 1c 08 8b 4d ec 8a 1c 08 80 f3 ?? 88 1c 08 40 3b c2 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 44 24 18 43 c6 44 24 19 72 c6 44 24 1b 61 88 4c 24 1c c6 44 24 1e 45 c6 44 24 1f 76 c6 44 24 21 6e 88 4c 24 22 c6 44 24 23 41 88 5c 24 24 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ASDE_2147895489_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ASDE!MTB"
        threat_id = "2147895489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fuckyou" ascii //weight: 1
        $x_2_2 = "Program Files\\Common Files\\scvhost.exe" ascii //weight: 2
        $x_1_3 = "taskkill /f /im rundll32.exe" ascii //weight: 1
        $x_1_4 = "Gh0st RAT" ascii //weight: 1
        $x_2_5 = {4b 37 c9 b1 b6 be 00 00 4b 37 54 53 65 63 75 72 69 74 79 2e 65 78 65 00 43 4d 43 c9 b1 b6 be 00 43 4d 43 54 72 61 79 49 63 6f 6e 2e 65 78 65 00 46 2d 50 52 4f 54 c9 b1 b6 be 00 00 46 2d 50 52 4f 54 2e 45 58 45 00 00 43 6f 72 61 6e 74 69 32 30 31 32 c9 b1 b6 be 00 43 6f 72 61 6e 74 69 43 6f 6e 74 72 6f 6c 43 65 6e 74 65 72 33 32 2e 65 78 65}  //weight: 2, accuracy: High
        $x_2_6 = {5b 50 61 75 73 65 20 42 72 65 61 6b 5d 00 00 00 5b 53 68 69 66 74 5d 00 5b 41 6c 74 5d 00 00 00 5b 43 4c 45 41 52 5d 00 5b 42 41 43 4b 53 50 41 43 45 5d 00 5b 44 45 4c 45 54 45 5d 00 00 00 00 5b 49 4e 53 45 52 54 5d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ASDG_2147895720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ASDG!MTB"
        threat_id = "2147895720"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4d 08 2b cb 8a 14 01 80 f2 62 88 10 40 4f 75}  //weight: 2, accuracy: High
        $x_1_2 = "fuckyou" ascii //weight: 1
        $x_1_3 = "Program Files\\Common Files\\scvhost.exe" ascii //weight: 1
        $x_1_4 = "[Pause Break]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ASDG_2147895720_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ASDG!MTB"
        threat_id = "2147895720"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff d6 8b 55 fc 8b 45 f8 0f b6 0c 17 0f b6 04 10 03 c8 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 0f b6 04 11 30 83 [0-4] 43 8b 4d f8 81 fb 1c 06 00 00 0f 82}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 0a 32 4d ef 02 4d ef 88 0a c3 8b 45 e4 ff 45 e8 40 c7 45 fc 01 00 00 00 eb}  //weight: 2, accuracy: High
        $x_1_3 = "Fuck" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_GW_2147896103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.GW!MTB"
        threat_id = "2147896103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 0c 24 3b c8 49 81 c4 04 00 00 00 33 cd 41 f7 c1 6d 4d 43 46 e9 a8 9f 01 00}  //weight: 10, accuracy: High
        $x_1_2 = "TelegramDll.dll" ascii //weight: 1
        $x_1_3 = "CreateProcess" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "cYreenQillm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_Y_2147897330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.Y!MTB"
        threat_id = "2147897330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 30 58 02 10 56 e8 ?? ?? 00 00 83 c4 08 85 c0 0f 85 ?? ?? 00 00 68 44 58 02 10 56 e8 ?? ?? 00 00 83 c4 08 85 c0 0f 85 ?? ?? 00 00 68 60 58 02 10 56 e8 ?? ?? 00 00 83 c4 08 85 c0 0f 85 ?? ?? 00 00 68 70 58 02 10 56 e8 ?? ?? 00 00 83 c4 08 85 c0 0f 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_X_2147899585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.X!MTB"
        threat_id = "2147899585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {99 f7 f9 8b 45 ?? 8b 3d ?? ?? ?? ?? 8b ca 33 d2 33 c8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_CCGC_2147900136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.CCGC!MTB"
        threat_id = "2147900136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 10 01 83 c0 ?? 0f 57 c1 66 0f fc c1 0f 11 01 0f 10 41 ?? 0f 57 c1 66 0f fc c1 0f 11 41 ?? 0f 10 41 ?? 0f 57 c1 66 0f fc c1 0f 11 41 ?? 0f 10 41 ?? 0f 57 c1 66 0f fc c1 0f 11 41 ?? 83 c1 ?? 3b c7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_CCGD_2147900140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.CCGD!MTB"
        threat_id = "2147900140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /C  regedit /s Uac.reg" ascii //weight: 1
        $x_1_2 = "%s\\%d.bak" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "chrome.exe" ascii //weight: 1
        $x_1_5 = "firefox.exe" ascii //weight: 1
        $x_1_6 = "QQBrowser.exe" ascii //weight: 1
        $x_1_7 = "NOD32" ascii //weight: 1
        $x_1_8 = "Avast" ascii //weight: 1
        $x_1_9 = "Avira" ascii //weight: 1
        $x_1_10 = "K7TSecurity.exe" ascii //weight: 1
        $x_1_11 = "QUICK HEAL" ascii //weight: 1
        $x_1_12 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_CCGE_2147900194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.CCGE!MTB"
        threat_id = "2147900194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 ec 4b c6 45 ed 45 c6 45 ee 52 c6 45 ef 4e c6 45 f0 45 c6 45 f1 4c c6 45 f2 33 c6 45 f3 32 c6 45 f4 2e c6 45 f5 64 c6 45 f6 6c c6 45 f7 6c 88 5d f8 c6 45 d0 43 c6 45 d1 72 c6 45 d2 65 c6 45 d3 61 c6 45 d4 74 c6 45 d5 65 c6 45 d6 54 c6 45 d7 6f c6 45 d8 6f c6 45 d9 6c c6 45 da 68 c6 45 db 65 c6 45 dc 6c c6 45 dd 70 c6 45 de 33 c6 45 df 32 c6 45 e0 53 c6 45 e1 6e c6 45 e2 61 c6 45 e3 70 c6 45 e4 73 c6 45 e5 68 c6 45 e6 6f c6 45 e7 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_CCGF_2147900210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.CCGF!MTB"
        threat_id = "2147900210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d3 0f 28 05 ?? ?? ?? ?? 6a 18 0f 11 45 c8 c7 45 ?? 63 2f 2f 44 c7 45 ?? 6f 63 75 6d c7 45 ?? 65 6e 74 73 66 c7 45 ?? 2f 2f c6 45 e6 00 ff d3}  //weight: 1, accuracy: Low
        $x_1_2 = {68 f8 f5 40 00 68 70 f6 40 00 68 80 f6 40 00 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ASDI_2147900316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ASDI!MTB"
        threat_id = "2147900316"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2b cf 8a 14 01 80 f2 62 88 10 40 4e 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_VR_2147900481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.VR!MTB"
        threat_id = "2147900481"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 52 01 3a c3 8c cc 83 c1 05}  //weight: 1, accuracy: High
        $x_1_2 = {38 a7 8b 4e 24 c3 26 2c 8b 41 0c c3 22 8d 50 ff c3 4c 89 51 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_CCGZ_2147901041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.CCGZ!MTB"
        threat_id = "2147901041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 33 ff 8a 87 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 47 6a 00 ff d3 b8 ?? ?? ?? ?? f7 e6 c1 ea 02 8d 0c 92 8b d6 2b d1 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MAN_2147901638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MAN!MTB"
        threat_id = "2147901638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 01 8d 95 f8 fe ff ff 12 00 6a 00 6a 00 6a 03 6a 00 [0-9] 68 00 00 00 80 52 ff 15 ?? ?? ?? ?? 8b f0 83 fe ff 75}  //weight: 1, accuracy: Low
        $x_1_2 = "GetDriveTypeA" ascii //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "software\\mICROSOFT\\wINDOWS nt\\cURRENTvERSION\\sVCHOST" ascii //weight: 1
        $x_1_6 = "MapVirtualKeyA" ascii //weight: 1
        $x_1_7 = "CreateMutexA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MAK_2147901655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MAK!MTB"
        threat_id = "2147901655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 08 8d 0c 06 0f b6 04 06 c1 e8 04 83 f8 09 7e ?? 04 37 eb ?? 04 30 88 02 8a 01 83 e0 0f 83 f8 09 7e ?? 04 37 eb ?? 04 30 88 42 01 46 42 42 3b 74 24 10 7c}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
        $x_1_4 = "SetThreadContext" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ML_2147901833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ML!MTB"
        threat_id = "2147901833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0b 8b 73 04 8b 7c 24 1c 8b d1 03 f7 8b f8 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 89 43 f8 8b 4c 24 24 8b 44 24 10 40 83 c3 28 8b 11 33 c9 89 44 24 10 66 8b 4a 06 3b c1 0f 8c}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4e 54 8b 74 24 3c 55 8b 7e 3c 03 cf 8b f8 8b d1 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 8b 4c 24 40 8b 74 24 1c 56 51 8b 51 3c 03 c2 89 45 00 89 58 34 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ASDJ_2147902480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ASDJ!MTB"
        threat_id = "2147902480"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 4d 08 8a 14 11 32 94 ?? ?? ff ff ff 8b 85 ?? ?? ff ff 25 ff ?? ?? ?? 8b 4d 08 88 14 01}  //weight: 3, accuracy: Low
        $x_2_2 = "SystemRoot%\\System32\\svchost.exe -k sougou" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ASDK_2147902993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ASDK!MTB"
        threat_id = "2147902993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {32 d8 8a 0c b9 32 4d f0 02 cb 32 d1 8b 4d fc 28 16 0f b6 06}  //weight: 3, accuracy: High
        $x_1_2 = "jinjin.com" ascii //weight: 1
        $x_1_3 = "fuckyou" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ASDL_2147903145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ASDL!MTB"
        threat_id = "2147903145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 78 da 04 00 6a 00 ff 15 ?? ?? ?? 00 50 ff 15}  //weight: 2, accuracy: Low
        $x_1_2 = {33 c0 56 8b f1 57 b9 9e 36 01 00 8d 7e 10}  //weight: 1, accuracy: High
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ASDM_2147904371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ASDM!MTB"
        threat_id = "2147904371"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {03 c8 33 d1 8b 4d 08 03 4d f8}  //weight: 5, accuracy: High
        $x_5_2 = {6a 04 68 00 20 00 00 8b 45 d0 8b 48 50 51 8b 55 d0 8b 42 34 50 ff 15}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_CCHZ_2147905362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.CCHZ!MTB"
        threat_id = "2147905362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b e5 5d c3 6a 00 6a 02 c7 85 ?? ?? ?? ?? 2c 02 00 00 ff 15 ?? ?? ?? ?? 8b f8 83 ff ff 0f 84 ?? ?? 00 00 8d 85 ?? ?? ?? ?? 50 57 ff 15 ?? ?? 42 00 8b 35 ?? ?? 42 00 85 c0 74 59 8b 1d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ASDN_2147905951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ASDN!MTB"
        threat_id = "2147905951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 64 24 00 80 b4 05 ?? ?? ?? ?? ?? 40 3d c0 67 0f 00 75}  //weight: 5, accuracy: Low
        $x_5_2 = {6a 40 68 00 30 00 00 50 6a 00 ff 15 ?? ?? ?? ?? 8b f0 68 c0 67 0f 00 8d 85 ?? ?? ?? ff 50 56 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_W_2147906161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.W!MTB"
        threat_id = "2147906161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f6 d8 fe ca fe c0 d0 da 34 ?? 84 f7 c1 da ?? f8 28 da 30 c3 fe ca 66 0f bd d6 0f b6 c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_V_2147906187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.V!MTB"
        threat_id = "2147906187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f bc fd 01 ff 29 d1 f7 d8 8d 45 ?? 66 0f ac e7 ?? d3 cf 24 fc 66 0f be f8 66 0f ad cf 66 81 df ?? ?? 29 c8 66 f7 d7 66 0f be f8 66 0f cf 66 0f be fa 89 c4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_U_2147908462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.U!MTB"
        threat_id = "2147908462"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6d 4d c1 50 ?? ?? c0 bf ?? ?? ?? ?? ?? 24 ?? fd ad 22 ff 69 a6 ?? ?? ?? ?? ?? ?? ?? ?? 3b c4 ce f8 58 d4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_T_2147908476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.T!MTB"
        threat_id = "2147908476"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3a f7 af 53 43 82 e2 ?? 27 ce 53 80 43}  //weight: 2, accuracy: Low
        $x_2_2 = {8d 3b fa ed 28 20 c9 27 96 11 98}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ASDO_2147909315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ASDO!MTB"
        threat_id = "2147909315"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4a f9 05 cf 37 7b fa 1d ef f7 c0 34 ed ad 2f 01 88 ?? ?? ?? ?? 35 48 df a7 61 93 3b 09}  //weight: 5, accuracy: Low
        $x_5_2 = {1d 06 26 94 7d 27 ed 15 10 43 10 55 bd 67 5b 53 a5 ba 20 74 8c a0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ASGH_2147912493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ASGH!MTB"
        threat_id = "2147912493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5d 8a 08 30 0a 90 55 8b ec 41 49 83 c4 04 83 c4 fc 90 90 8b e5 90 5d 8a 08 00 0a 55 90 8b ec 85 f6 56 5e 83 c4 06 83 c4 fa 90 90 8b e5 90 5d 42 40 4f 75 92}  //weight: 2, accuracy: High
        $x_2_2 = {50 88 55 c3 c6 45 b4 72 c6 45 b5 75 c6 45 b6 6e c6 45 b7 64 c6 45 b8 6c c6 45 b9 6c c6 45 ba 33 c6 45 bb 32 c6 45 bc 2e 88 5d bd c6 45 be 78 88 5d bf 51}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RZ_2147912873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RZ!MTB"
        threat_id = "2147912873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 5d e9 00 00 00 00 55 8b ec 53 56 57 83 cf ff e8 37 74 ed ff 8b f0 e8 ec 87 ed ff ff 75 14 8b 58 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AFF_2147913853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AFF!MTB"
        threat_id = "2147913853"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 0b 89 c2 83 c3 01 c1 ea 04 31 c8 c0 e9 04 83 e0 0f 33 14 85 e0 a6 44 00 89 d0 31 ca 83 e2 0f c1 e8 04 33 04 95 e0 a6 44 00 39 de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RP_2147917722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RP!MTB"
        threat_id = "2147917722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\Users\\Public\\Documents\\logo.cco" ascii //weight: 10
        $x_10_2 = "C:\\Users\\Public\\Documents\\logo.cco" wide //weight: 10
        $x_1_3 = "Parallels Software International Inc." ascii //weight: 1
        $x_1_4 = "innotek GmbH" ascii //weight: 1
        $x_1_5 = "Microsoft Corporation" ascii //weight: 1
        $x_1_6 = "VMware" ascii //weight: 1
        $x_1_7 = "Failed to query value: SystemManufacturer" ascii //weight: 1
        $x_1_8 = "HARDWARE\\DESCRIPTION\\System\\BIOS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_RP_2147917722_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.RP!MTB"
        threat_id = "2147917722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "165"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "C:\\Users\\inx.cod" ascii //weight: 100
        $x_10_2 = "wmic bios get manufacturer" ascii //weight: 10
        $x_10_3 = "VMware" ascii //weight: 10
        $x_10_4 = "Virtual" ascii //weight: 10
        $x_10_5 = "Microsoft Corporation" ascii //weight: 10
        $x_10_6 = "innotek GmbH" ascii //weight: 10
        $x_10_7 = "Parallels Software International Inc." ascii //weight: 10
        $x_1_8 = "\\VC\\include\\streambuf" ascii //weight: 1
        $x_1_9 = "C:\\INTERNAL\\REMOTE.EXE" wide //weight: 1
        $x_1_10 = "strcat_s(CommandLine, CommandLineSize, cmdstring)" wide //weight: 1
        $x_1_11 = "strcat_s(CommandLine, CommandLineSize, \" /c \")" wide //weight: 1
        $x_1_12 = "strcpy_s(CommandLine, CommandLineSize, cmdexe)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_MKV_2147918906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.MKV!MTB"
        threat_id = "2147918906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2b f7 89 55 e4 8b 43 14 8d 0c 3e 83 e1 03 8a 04 01 30 07 47 4a 75 ee}  //weight: 5, accuracy: High
        $x_5_2 = {8b 4d 0c 8b c6 83 e0 03 8a 04 08 30 04 1e 46 3b f2 7c f0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_GNN_2147919079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.GNN!MTB"
        threat_id = "2147919079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 45 ec 50 bf ?? ?? ?? ?? 57 8d 85 ?? ?? ?? ?? 50 56 8b 35 ?? ?? ?? ?? ?? ?? 39 5d ec ?? ?? 53 ff 75 ec 8d 85 ?? ?? ?? ?? 50 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8d 45 ec 50 57 8d 85 ?? ?? ?? ?? 50 ff 75 e8 ff d6 85 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ASDH_2147920616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ASDH!MTB"
        threat_id = "2147920616"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 08 8a 10 8a 4d ef 32 d1 02 d1 88 10 40 89 45 08 c7 45 fc 01 00 00 00 b8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ARA_2147923217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ARA!MTB"
        threat_id = "2147923217"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 7d 08 b8 ?? ?? ?? ?? 80 c2 3d 30 14 31 8b ce f7 e6 c1 ea 03 8d 04 92 03 c0 2b c8 f7 d9 1b c9 46 23 d9 3b f7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_ARA_2147923217_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.ARA!MTB"
        threat_id = "2147923217"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 f2 58 8b 45 08 03 45 e8 88 10 eb d8}  //weight: 2, accuracy: High
        $x_2_2 = {8b 45 08 03 c1 80 30 58 41 3b 4d 0c 7c f2}  //weight: 2, accuracy: High
        $x_2_3 = {8b 45 10 8a 04 02 30 01 46 eb e0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Farfli_AHG_2147929180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AHG!MTB"
        threat_id = "2147929180"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 ec 8b 48 08 8b 45 14 0f b6 04 ?? 99 ?? 15 18 00 00 f7 ?? 8b c6 6a 0a 80 c2 3d 30 14 31 99 59 f7 f9 ?? 85 d2 75}  //weight: 5, accuracy: Low
        $x_5_2 = {6a 04 68 00 10 00 00 53 6a 00 ff 15 ?? ?? ?? 00 8b ce 8b f8 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_EAG_2147939210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.EAG!MTB"
        threat_id = "2147939210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 0a 32 4d ef 02 4d ef 88 0a 42 89 55 08 c3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_KK_2147949264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.KK!MTB"
        threat_id = "2147949264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {8d 85 30 fe ff ff 50 ff d7 8d 85 30 fe ff ff 50 ff d3 6a 00 6a 00 6a 00 8d 85 30 fe ff ff 50 ff d6 85 c0}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_KK_2147949264_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.KK!MTB"
        threat_id = "2147949264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {99 b9 1a 00 00 00 f7 f9 46 3b f7 8a 54 14 10 88 54 1e ff}  //weight: 20, accuracy: High
        $x_10_2 = "ekimhuqcroanflvzgdjtxypswb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_KK_2147949264_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.KK!MTB"
        threat_id = "2147949264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {89 7e 44 89 7e 48 89 7e 54 89 7e 58 89 7e 5c 89 7e 60 c7 46 64 03 00 00 00}  //weight: 20, accuracy: High
        $x_15_2 = {6a 00 68 18 01 00 00 8d 85 e8 fc ff ff 50 53 56 ff}  //weight: 15, accuracy: High
        $x_10_3 = "C:\\Users\\Public\\Documents\\QeiySBcapV.dat" ascii //weight: 10
        $x_5_4 = "C:\\Users\\Public\\Documents\\WindowsData\\kail.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_KAB_2147953716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.KAB!MTB"
        threat_id = "2147953716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {30 11 f7 65 0c 8b 4d 08 8b 45 0c 41 c1 ea ?? 40 c7 45 08 00 00 00 00 89 45 0c 8d 14 92 03 d2 3b fa 8b 55 08 0f 45 d1 89 55 08 3b c3 7c}  //weight: 20, accuracy: Low
        $x_10_2 = {8b f8 8b 4d 0c 8b 45 14 03 4e 08 0f b6 04 02 33 d2 f7 75 10 b8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_LM_2147957472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.LM!MTB"
        threat_id = "2147957472"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8b 45 18 0f b6 04 06 8b 57 08 8d 3c 11 99 bb c5 07 00 00 f7 fb b8 ?? ?? ?? ?? 46 80 c2 36 30 17 f7 e1 c1 ea 03}  //weight: 20, accuracy: Low
        $x_10_2 = {03 d2 8b c1 2b c2 75 ?? 33 f6 8b 5d 10 8b 7d 08 41 3b cb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AHD_2147959116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AHD!MTB"
        threat_id = "2147959116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {f7 f9 8b 45 ec 2a d0 88 14 38 40 3b 45 fc 89 45 ec 72}  //weight: 30, accuracy: High
        $x_20_2 = {8b 38 03 7d 8c 6a ?? 59 be ?? ?? ?? ?? f3 a5 66 a5 42 83 45 8c ?? 3b 50 ?? 72}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfli_AFA_2147959558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfli.AFA!MTB"
        threat_id = "2147959558"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 50 6a 02 68 d0 c0 41 00 56 ff d7 56 ff 15 ?? ?? ?? ?? 6a 08 be ac c0 41 00 59 8d bd 5c ff ff ff f3 a5 66 a5 6a 40 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

