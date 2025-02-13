rule Trojan_Win32_FlyStudio_K_2147622964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.K"
        threat_id = "2147622964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 25 25 00 62 6f 64 79 00 69 6e 6e 65 72 48 54 4d 4c 00 6e 47 3a 35 5f 6c 6e 3d 3d 32 6d 43 32}  //weight: 1, accuracy: High
        $x_1_2 = {27 7b 27 00 47 30 30 47 4c 45 00 69 78 65 78 57}  //weight: 1, accuracy: High
        $x_1_3 = {4e 65 77 53 6f 63 6b 00 53 6f 66 74 77 61 72 65 5c 46 6c 79 53 6b 79 5c 45 5c 49 6e 73 74 61 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_R_2147627912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.R"
        threat_id = "2147627912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "|SNsse|c:\\windows|" ascii //weight: 2
        $x_1_2 = "MZO03.exe" ascii //weight: 1
        $x_1_3 = {48 54 54 50 2f 31 2e 31 00 65 70 74 3a 20}  //weight: 1, accuracy: High
        $x_1_4 = "internet explorer_server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FlyStudio_T_2147641283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.T"
        threat_id = "2147641283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\igfxtray" ascii //weight: 3
        $x_3_2 = "\\zhuomian.jpg" ascii //weight: 3
        $x_1_3 = "CreateRemoteThread" ascii //weight: 1
        $x_2_4 = "ERawSock" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_T_2147641283_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.T"
        threat_id = "2147641283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 02 00 00 80 6a 00 68 00 00 00 00 68 04 00 00 80 6a 00 68 ?? ?? ?? 00 68 03 00 00 00 bb ?? ?? ?? 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {68 04 00 00 80 6a 00 68 ?? ?? ?? 00 68 01 00 00 00 b8 01 00 00 00 bb ?? ?? ?? 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 31 31 31 6d 2e 69 6e 66 6f 2f 76 69 70 2f 76 69 70 ?? 2e 6a 70 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_CE_2147805530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.CE!MTB"
        threat_id = "2147805530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 02 03 d0 03 d8 2b e8 3b e8 88 0b 77 f1}  //weight: 1, accuracy: High
        $x_1_2 = {33 f8 d1 e8 85 c7 75 f8 8b 54 24 18 bd 01 00 00 00 8b cb 33 f8 d3 e5 8b 8c 94 ?? ?? ?? ?? 8d 84 94 ?? ?? ?? ?? 89 7c 24 38 4d 23 ef 3b e9 74 20}  //weight: 1, accuracy: Low
        $x_1_3 = "www.dywt.com.cn" ascii //weight: 1
        $x_1_4 = "BBtools.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_CH_2147808317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.CH!MTB"
        threat_id = "2147808317"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "inject.exe" ascii //weight: 1
        $x_1_2 = "https://gitee.com/jsmh/hwid/raw/master/hwid.txt" ascii //weight: 1
        $x_1_3 = "jsmh ToolChest\\AntiBan.dll" ascii //weight: 1
        $x_1_4 = "https://wwr.lanzoui.com" ascii //weight: 1
        $x_1_5 = "https://res.abeim.cn/api-lanzou_jx?url=https://wwr.lanzoui.com/iuuIqscn0ra" ascii //weight: 1
        $x_1_6 = "VMProtect begin" ascii //weight: 1
        $x_1_7 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_8 = "QueryPerformanceCounter" ascii //weight: 1
        $x_1_9 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_CC_2147808322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.CC!MTB"
        threat_id = "2147808322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 48 ff 8a 58 fe 02 d9 88 58 fe 8a 18 02 d9 88 18 03 c6 4a 75 ea}  //weight: 1, accuracy: High
        $x_1_2 = {8b d0 33 db 8a 19 81 e2 ff 00 00 00 33 d3 c1 e8 08 8b 14 95 60 8b 60 00 33 c2 41 4e 75 e2}  //weight: 1, accuracy: High
        $x_1_3 = {8a 1e 8a c8 d2 eb 80 e3 0f 83 f8 04 88 5d 00 75 05}  //weight: 1, accuracy: High
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_DU_2147888142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.DU!MTB"
        threat_id = "2147888142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f6 d1 66 85 d1 32 d9 89 04 0c 66 f7 d9 66 0f ab e9 66 81 e9 47 46 81 ed 04 00 00 00 8b 4c 25 00 f7 c4 b2 4d 81 04 f5 33 cb 66 81 ff 93 72 66 85 f1 f7 d9 3d 7e 2f 08 66 81 f1 a3 7b 0d 58 e9}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4c 25 00 8d ad 04 00 00 00 33 cb f7 d9 85 e3 f5 81 c1 91 7b 69 50 f8 f5 f9 d1 c9 41 f5 33 d9 03 f1 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_DT_2147888640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.DT!MTB"
        threat_id = "2147888640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d 0d 32 d3 cf 78 98 63 3d 6e d7 33 40 21 ea 5e 67 06 8c 7c 83 f7 71 e2 cd 49 83 2b 2f 49 2e d8 73 ce 0c ed be 7e 19 ac 0f f9 99 7c c2 4f 7e e4 d7 da f6 af ba 05 78}  //weight: 1, accuracy: High
        $x_1_2 = {b1 b2 a7 0a e5 a4 14 f1 8f c1 6c d8 1e e7 90 bc 23 32 de 08 c9 bf 90 e5 bf 57 ca 5a b0 37 e6 30 01 dd 5d 3f 1a ac 44 12 c3 31}  //weight: 1, accuracy: High
        $x_1_3 = {c0 53 f8 e3 e0 ed d6 37 8c f8 d9 2d 0d 3f 24 08 bf 0e 4e 0b 69 ba 38 3e 9b c0 fe 8b f3 7e f7 53 9e 79 29 b7 ea 41 da e5 03 09 44 0d 81 6a d2 83 d2 5d 42 f4 75 b0}  //weight: 1, accuracy: High
        $x_1_4 = {59 79 30 91 a5 62 31 f9 89 36 93 d8 9f 11 76 0c a5 30 5a 62 93 c7 0e c8 22 b8 74 b2 6a 0a 6a bc 54 38 74 4f e7 41 7f 01 b8 f3 f2 c4 46 45 b1 e0 ab ba 37 89 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_FlyStudio_DV_2147888807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.DV!MTB"
        threat_id = "2147888807"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TRILAAAAgDEyMzQAAAEBAAAA" ascii //weight: 1
        $x_1_2 = "76 78 6C 5F 6E 70 63 20" ascii //weight: 1
        $x_1_3 = "50 C7 85 EC F7 FF FF 64 00 63" ascii //weight: 1
        $x_1_4 = "@@8B 06 8D 4D D4 83 C4 0C 51 8B" ascii //weight: 1
        $x_1_5 = "7E 45 F4 66 0F D6 80 58 46" ascii //weight: 1
        $x_1_6 = "55 8B EC 83 EC 08 0F 57 C9 53" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_DW_2147891638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.DW!MTB"
        threat_id = "2147891638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "t.qq.com/mimahenjiandan" ascii //weight: 1
        $x_1_2 = "r=1326025761453" ascii //weight: 1
        $x_1_3 = "m.qzone.qq.com/cgi-bin/new/msgb_addanswer.cgi" ascii //weight: 1
        $x_1_4 = "user.qzone.qq.com/827822285" ascii //weight: 1
        $x_1_5 = "ccbfd68b5fceb62707a9e4ce87b8c813" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_DX_2147891640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.DX!MTB"
        threat_id = "2147891640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shutdown.exe -s -t 60" ascii //weight: 1
        $x_1_2 = "0B3AA075E30D18D8D4F69D426C04AB603985A4FEE905C219280A74EFADCAD60B5D7F927E1D7D8D7885B08478F6FBB73733142B3E5385DBC864181FA1999AAFBFA0CB" ascii //weight: 1
        $x_1_3 = "xiaosicp.taobao.com" ascii //weight: 1
        $x_1_4 = "E9326F3E-A23C-46D3-9C20-3AE825EFA0A7" ascii //weight: 1
        $x_1_5 = "{9DA96BF9CEBD45c5BFCF94CBE61671F5}" ascii //weight: 1
        $x_1_6 = "uin=573518915" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_DY_2147891674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.DY!MTB"
        threat_id = "2147891674"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b ec 68 02 00 00 80 6a 00 68 00 00 00 00 6a 00 6a 00 6a 00 68 01 00 01 00 68 03 00 01 06 68 04 00 01 52 68 03 00 00 00 bb}  //weight: 2, accuracy: High
        $x_1_2 = {6a 08 68 76 5d 01 16 68 04 00 01 52 e8}  //weight: 1, accuracy: High
        $x_1_3 = {35 31 31 34 2e 64 6c 6c 00 5f c6 f4 b6 af d7 d3 b3 cc d0 f2}  //weight: 1, accuracy: High
        $x_1_4 = {35 31 31 2e 64 6c 6c 00 5f c6 f4 b6 af d7 d3 b3 cc d0 f2}  //weight: 1, accuracy: High
        $x_1_5 = {54 50 30 30 30 30 2e 64 6c 6c 00 5f c6 f4 b6 af d7 d3 b3 cc d0 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FlyStudio_DZ_2147891675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.DZ!MTB"
        threat_id = "2147891675"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 02 00 00 80 6a 00 68 01 00 00 00 6a 00 6a 00 6a 00 68 01 00 01 00 68 03 00 01 06 68 04 00 01 52 68 03 00 00 00 bb}  //weight: 1, accuracy: High
        $x_1_2 = {6a ff 6a 08 68 5a 1b 01 16 68 04 00 01 52 e8}  //weight: 1, accuracy: High
        $x_1_3 = {31 2e 64 6c 6c 00 52 75 6e 44 6c 6c 48 6f 73 74 43 61 6c 6c 42 61 63 6b}  //weight: 1, accuracy: High
        $x_1_4 = "2F8761CF148F88C2640DBBA783EF2917" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_CB_2147892761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.CB!MTB"
        threat_id = "2147892761"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 6a 00 68 01 00 00 00 6a ff 6a 05 68 00 00 01 06 68 01 00 01 52 e8}  //weight: 1, accuracy: High
        $x_1_2 = "counter.sina.com.cn/ip" ascii //weight: 1
        $x_1_3 = "116.89.144.0/255" ascii //weight: 1
        $x_1_4 = "202.165.208.0/255" ascii //weight: 1
        $x_1_5 = "{A43E53FA-42E4-4f20-B26E-B5E59C8E48B9}" ascii //weight: 1
        $x_1_6 = "707ca37322474f6ca841f0e224f4b620" ascii //weight: 1
        $x_1_7 = "C:\\VOTEID.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_CF_2147892773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.CF!MTB"
        threat_id = "2147892773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 04 00 02 00 68 65 18 01 16 68 03 00 01 52 68 01 00 00 00 b8 01 00 00 00 bb}  //weight: 1, accuracy: High
        $x_1_2 = {68 05 00 01 00 68 09 00 01 16 68 03 00 01 52 68 01 00 00 00 bb}  //weight: 1, accuracy: High
        $x_1_3 = {55 8b ec 68 02 00 00 80 6a 00 68 00 00 00 00 6a 00 6a 00 6a 00 68 01 00 01 00 68 02 00 01 06 68 03 00 01 52 68 03 00 00 00 bb}  //weight: 1, accuracy: High
        $x_1_4 = "setl.fnr" ascii //weight: 1
        $x_1_5 = "5F99C1642A2F4e03850721B4F5D7C3F8" ascii //weight: 1
        $x_1_6 = "4BB4003860154917BC7D8230BF4FA58A" ascii //weight: 1
        $x_1_7 = "www.zhifu3158.cn/qqgaoji/csdfm.txt" ascii //weight: 1
        $x_1_8 = "c:\\Del.bat" ascii //weight: 1
        $x_1_9 = "list.qq.com/cgi-bin/qf_compose_send" ascii //weight: 1
        $x_1_10 = "del /q %temp%\\delay.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule Trojan_Win32_FlyStudio_NA_2147893670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.NA!MTB"
        threat_id = "2147893670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {74 06 81 cf ?? ?? ?? ?? 8b 4d dc 8b c1 c1 e0 ?? 8b 55 d8 03 c2 89 35 ?? ?? ?? ?? a3 04 f3 4f 00 89 0d ?? ?? ?? ?? 89 15 0c f3 4f 00 89 3d ?? ?? ?? ?? e8 f5 fe ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_CG_2147893816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.CG!MTB"
        threat_id = "2147893816"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c4 18 6a 00 6a 00 6a 00 68 01 00 01 00 68 00 00 01 06 68 01 00 01 52 68 02 00 00 00 bb}  //weight: 1, accuracy: High
        $x_1_2 = "lj.bat" ascii //weight: 1
        $x_1_3 = "user.qzone.qq.com/1239181712" ascii //weight: 1
        $x_1_4 = "del /f /q %userprofile%\\cookies\\*.*" ascii //weight: 1
        $x_1_5 = "www.cfyuefei.com/xiazai.html" ascii //weight: 1
        $x_1_6 = "vmip.taobao.com" ascii //weight: 1
        $x_1_7 = "www.logo193.com" ascii //weight: 1
        $x_1_8 = "C:\\wenben.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_DK_2147894258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.DK!MTB"
        threat_id = "2147894258"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shutdown.exe -s -t 60" ascii //weight: 1
        $x_1_2 = "0B3AA075E30D18D2D1B7980D760FB63B7489A6BC16D46CB268533EA2B9CCD04B476294631D7BDA2981E28B7AF4F8FD68264B76" ascii //weight: 1
        $x_1_3 = "xiaosicp.taobao.com" ascii //weight: 1
        $x_1_4 = "E9326F3E-A23C-46D3-9C20-3AE825EFA0A7" ascii //weight: 1
        $x_1_5 = "{9DA96BF9CEBD45c5BFCF94CBE61671F5}" ascii //weight: 1
        $x_1_6 = "uin=573518915" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_ASDE_2147896950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.ASDE!MTB"
        threat_id = "2147896950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sys.wk7b.com:8090" ascii //weight: 1
        $x_1_2 = "3598123.exe" ascii //weight: 1
        $x_1_3 = "www.baidupcs.com/file" ascii //weight: 1
        $x_1_4 = "{EB5A8679-6C96-4465-A329-7911418F2582}" ascii //weight: 1
        $x_1_5 = "0DD316AB105442f882C4B535F45E63CB" ascii //weight: 1
        $x_1_6 = "js.users.51.la/14911066.js" ascii //weight: 1
        $x_1_7 = "wk7b_update.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_NFD_2147900926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.NFD!MTB"
        threat_id = "2147900926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 85 f4 fd ff ff 50 e8 bc 00 00 00 33 db 39 9e ?? ?? ?? ?? 75 13 8d 85 ?? ?? ?? ?? 50 e8 ed 7c fe ff}  //weight: 5, accuracy: Low
        $x_1_2 = "eyuyan.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_AFL_2147902766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.AFL!MTB"
        threat_id = "2147902766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 ff 15 38 65 48 00 8b 4c 24 04 6a 01 6a 00 6a 00 51 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_AFL_2147902766_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.AFL!MTB"
        threat_id = "2147902766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {56 ff d3 8b f0 3b f7 74 3f 6a 02 56 e8 6b fe ff ff 85 c0 74 33 85 ff 74 1f 6a f0 57 ff 15 48 85 4f 00 a9 00 00 00 40 74 0f 57 ff d3 8b f8 ff 15}  //weight: 2, accuracy: High
        $x_1_2 = {8b f0 85 f6 74 45 56 ff 15 34 86 4f 00 66 3d ff ff 74 2f 6a f0 56 ff 15 48 85 4f 00 a9 00 00 00 10 74 1f 8d 45 f0 50 56 ff 15 80 85 4f 00 ff 75 10 8d 45 f0 ff 75 0c 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_NT_2147908641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.NT!MTB"
        threat_id = "2147908641"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {85 c0 89 47 ?? 75 05 e8 1f 46 ff ff 8b 03 8b c8 69 c9 ?? ?? ?? ?? 03 4e 0c c1 e1 ?? 51 8b 4f 0c 6a ?? 8d 04 81 50 e8 f0 91 fe ff 8b 46 0c 83 c4 ?? 89 03 57 ff 36}  //weight: 5, accuracy: Low
        $x_1_2 = "dywt.com.cn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_AFY_2147911888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.AFY!MTB"
        threat_id = "2147911888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 04 56 25 ff 00 00 00 6a 00 50 8b f1 6a 00 ff 15 f0 a1 53 00 89 06 8b c6 5e}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 04 56 68 f4 3a 99 00 8b f1 68 ff ff ff 7f 50 6a 00 89 06 ff 15 20 a3 53 00 89 46 04 8b c6 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_AFY_2147911888_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.AFY!MTB"
        threat_id = "2147911888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 6a 00 51 68 c0 5c 4e 00 6a 00 ff 15 ?? ?? ?? ?? 8b f0 83 fe 20 0f 87 e4 00 00 00 8d 54 24 14 8b cf 52 68 b8 5c 4e 00 68 00 00 00 80 e8 ?? ?? ?? ?? 85 c0 0f 85 c6 00 00 00 8b 1d 9c 62 4a 00 8d 44 24 14 68 a4 5c 4e 00 50 ff d3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_AFS_2147914014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.AFS!MTB"
        threat_id = "2147914014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 d8 1b c0 8b 7f 08 25 00 00 00 08 50 6a 01 ff 75 14 ff 75 10 ff 75 1c ff 75 0c 57 ff 15 18 59 60 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 46 34 83 c4 0c 89 46 38 8d 45 fc 50 8b 45 08 2b fb 03 c3 57 50 ff 76 14 ff 15 20 59 60 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_MA_2147917646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.MA!MTB"
        threat_id = "2147917646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "txt.ziboshuozuan.com/dxd" ascii //weight: 1
        $x_1_2 = "xiazaiba.com/html/" ascii //weight: 1
        $x_1_3 = "WinHttp.WinHttpRequest.5.1" ascii //weight: 1
        $x_1_4 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 1
        $x_1_5 = "cmd.exe /c del" ascii //weight: 1
        $x_1_6 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)" ascii //weight: 1
        $x_1_7 = "mshta.exe" ascii //weight: 1
        $x_1_8 = "Set WshShell = CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_9 = "WshShell.Exec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_AT_2147919689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.AT!MTB"
        threat_id = "2147919689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 42 e8 67 67 e6 ac 04 04 c4 c4 c4 47 8c 9b 2c 96 a6 a5 d6 28 48 48 48 e9 e9 54 e7 15 cb c3 89 68 4c 42 96 67 67 67 49 78 c4 6f 6f 6f 78 e0 7f db 05 23 7e b5 5d 5d 65 1f 84 66 72 c2 8c 09 2b 3c 9e 42 96 67 67 67 f4 35 1c 78 2a 2a 78 44 cd 10 85 1d 05 db 05 23 7e 5d 84 66 ff 1d 15 09 cf 48 ef 42 96 67 67 67 49 ce bf bf bf 2a 44 87 88 19 10 8e 8e 10 7f 23 34 62}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyStudio_ASDF_2147920384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.ASDF!MTB"
        threat_id = "2147920384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Dear Cracker , Please immediately stop the anti compiler behavior" ascii //weight: 1
        $x_1_2 = "Anti cracking service By" ascii //weight: 1
        $x_1_3 = "www.you-m.com/do.aspx" ascii //weight: 1
        $x_1_4 = "8d070bdf16538b4" ascii //weight: 1
        $x_1_5 = "Don't try do it!" ascii //weight: 1
        $x_2_6 = {6a 13 68 32 8a 01 16 68 01 00 01 52 e8 ?? ?? ?? 00 83 c4 10 68 01 03 00 80 6a 00 50 68 0e 00 01 00 68 32 8a 01 16 68 01 00 01 52 68 02 00 00 00 bb}  //weight: 2, accuracy: Low
        $x_2_7 = {83 c4 04 6a 00 ff 75 f0 6a ff 6a 08 68 a6 05 02 16 68 01 00 01 52 e8 ?? ?? ?? 00 83 c4 18 8b 5d f0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FlyStudio_CZ_2147921604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.CZ!MTB"
        threat_id = "2147921604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_EL_HideOwner" ascii //weight: 1
        $x_5_2 = "jfUjcOpjOkcGlfLlfLlfLkdKlfLxqVrlMqmNmjKjcIoiThdV" ascii //weight: 5
        $x_5_3 = "MiCCPPhotoshop ICC profile" ascii //weight: 5
        $x_1_4 = "\\dnf.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FlyStudio_NFA_2147927970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyStudio.NFA!MTB"
        threat_id = "2147927970"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyStudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {eb 02 33 f6 8b 45 08 83 4d fc ?? 89 46 08 8d 45 08 68 38 c9 5a 00}  //weight: 5, accuracy: Low
        $x_1_2 = "zheng" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

