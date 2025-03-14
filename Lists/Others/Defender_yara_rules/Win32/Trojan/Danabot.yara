rule Trojan_Win32_Danabot_F_2147731097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.F"
        threat_id = "2147731097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 fe 00 74 36 29 c0 48 23 02 83 ea fc f7 d8 83 e8 26 8d 40 fe 83 c0 01 29 f8 6a ff 5f 21 c7 c7 41 00 00 00 00 00 31 01 83 c1 04 83 ee 04 8d 05 0f 45 41 00 2d 65 98 00 00 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_G_2147731135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.G"
        threat_id = "2147731135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 fe 00 74 36 29 c0 48 23 02 83 ea fc f7 d8 83 e8 26 8d 40 fe 83 c0 01 29 f8 6a ff 5f 21 c7 c7 41 00 00 00 00 00 31 01 83 c1 04 83 ee 04 8d 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_K_2147740595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.K"
        threat_id = "2147740595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Disable-ComputerRestore \"C:\\\"" ascii //weight: 1
        $x_1_2 = "powershell.exe -ExecutionPolicy Bypass" ascii //weight: 1
        $x_1_3 = "taskkill /F /IM TeamViewer.exe" ascii //weight: 1
        $x_1_4 = "taskkill /F /IM jusched.exe" ascii //weight: 1
        $x_1_5 = "net stop mikroclientwservice" ascii //weight: 1
        $x_1_6 = "net stop MSSQL$MIKRO" ascii //weight: 1
        $x_1_7 = "net stop foxitreaderservice" ascii //weight: 1
        $x_1_8 = "Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f" ascii //weight: 1
        $x_1_9 = "Advanced\" /v ShowSuperHidden /t REG_DWORD /d 1 /f" ascii //weight: 1
        $x_2_10 = "HowToBackFiles.txt" ascii //weight: 2
        $x_2_11 = "@protonmail.com" ascii //weight: 2
        $x_2_12 = "Encrypter" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Danabot_L_2147742253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.L!dha"
        threat_id = "2147742253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\source\\New\\DanBot\\" ascii //weight: 2
        $x_2_2 = "ipconfig /flushdns & exit" wide //weight: 2
        $x_2_3 = "shell.Run \"cmd /k VMWares.bat\",0,True" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_G_2147742900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.G!MTB"
        threat_id = "2147742900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {85 c0 74 68 85 d2 74 64 49 7c 61 56 53 8b 72 fc 8b 58 fc 29 ce d1 e1 01 ca 39 de 7c 46 85 db 7e}  //weight: 1, accuracy: High
        $x_1_2 = {53 65 72 76 69 63 65 4d 61 69 6e 00 5f 5f 64 62 6b 5f 66 63 61 6c 6c 5f 77 72 61 70 70 65 72 00 64 62 6b 46 43 61 6c 6c 57 72 61 70 70 65 72 41 64 64 72 00 66 30 00 66 31 00 66 32 00 66 33 00 66 34 00 66 35 00 66 36 00 66 37 00 66 38 00 66 39 00 74 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_S_2147743645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.S!MSR"
        threat_id = "2147743645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "snxhk.dll" ascii //weight: 1
        $x_1_2 = "c:\\Users\\Public\\" ascii //weight: 1
        $x_1_3 = "/photo.png?id=%0.2X%0.8X%0.8X" ascii //weight: 1
        $x_1_4 = "lutheatre.com" ascii //weight: 1
        $x_1_5 = "mallesene.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_SA_2147743646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.SA!MSR"
        threat_id = "2147743646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MinornTheseRooglei" ascii //weight: 1
        $x_1_2 = "enowhnewc8are5h" ascii //weight: 1
        $x_1_3 = {61 6c 77 61 72 65 29 2c 32 30 30 39 2c 74 68 65 6c 55 [0-1] 69 63 65 6e 73 65 73 [0-1] 6f 72 65 64 51 4e}  //weight: 1, accuracy: Low
        $x_1_4 = "whenqubWindows-onlyIprocess" ascii //weight: 1
        $x_1_5 = "wherhw#@hre.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_RB_2147749140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.RB!MSR"
        threat_id = "2147749140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 29 eb 88 c4 c0 e8 04 75 ?? 88 e0 24 0f 75 ?? 49 75}  //weight: 1, accuracy: Low
        $x_1_2 = {83 eb 02 83 e9 04 8b 45 0c 8b 55 10 81 e0 ff 00 00 00 33 d2 8b 04 85 62 e1 54 00 89 01 8b 45 0c 8b 55 10 0f ac d0 08 c1 ea 08 89 45 0c 89 55 10 83 fb 02 7d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_2147751151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot!MTB"
        threat_id = "2147751151"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 fc 8d 34 03 e8 ?? ?? ?? ?? 30 06 b8 01 00 00 00 29 45 fc 39 7d fc 7d}  //weight: 2, accuracy: Low
        $x_2_2 = {30 04 3e b8 01 00 00 00 29 85 f4 f7 ff ff 8b b5 f4 f7 ff ff 3b f3 7d 05 00 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Danabot_DSK_2147751707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.DSK!MTB"
        threat_id = "2147751707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 08 8b 08 81 e9 92 27 01 00 8b 55 08 89 0a 8b e5 5d}  //weight: 2, accuracy: High
        $x_2_2 = {8b 45 fc 8d 34 07 e8 ?? ?? ?? ?? 30 06 83 6d fc 01 39 5d fc 7d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Danabot_KM_2147753110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.KM!MTB"
        threat_id = "2147753110"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d3 03 d0 81 e2 ff 00 00 00 81 3d ?? ?? ?? ?? 8a 08 00 00 89 15 ?? ?? ?? ?? 75 19 00 8b 0d ?? ?? ?? ?? 0f be 86 ?? ?? ?? ?? 8a 99 ?? ?? ?? ?? 03 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_KM_2147753110_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.KM!MTB"
        threat_id = "2147753110"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e2 89 74 24 ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 01 44 24 ?? a1 ?? ?? ?? ?? 3d 1a 0c 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_KM_2147753110_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.KM!MTB"
        threat_id = "2147753110"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 ea 05 03 55 ?? 89 55 ?? 8b 45 ?? 31 45 ?? 2b 75 ?? 8b 45 ?? d1 6d ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_KM_2147753110_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.KM!MTB"
        threat_id = "2147753110"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c0 7b 89 04 24 b8 f9 cd 03 00 01 04 24 83 2c 24 7b 8b 04 24 8a 04 08 88 04 0a 59 c3}  //weight: 2, accuracy: High
        $x_2_2 = {0f b6 d3 03 ca a3 ?? ?? ?? ?? 81 e1 ff 00 00 00 8a 81 ?? ?? ?? ?? 30 04 37 83 6d ?? 01 8b 75 ?? 85 f6 7d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Danabot_OE_2147754175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.OE!MTB"
        threat_id = "2147754175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 57 ff 15 2c 80 40 00 eb 15 8b 45 fc 8d 34 03 e8 6f fe ff ff 30 06 b8 01 00 00 00 29 45 fc 39 7d fc 7d e6 5f 5e 5b c9 c3}  //weight: 1, accuracy: High
        $x_1_2 = "SetProcessShutdownParameters" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_PVD_2147754535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.PVD!MTB"
        threat_id = "2147754535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 44 24 24 8b 8c 24 40 08 00 00 5f 5e 89 68 04 5d 89 18 5b 33 cc e8 ?? ?? ?? ?? 81 c4 34 08 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_AR_2147754671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.AR!MTB"
        threat_id = "2147754671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f0 03 4d ?? 8d 04 3b 33 c8 0f 57 c0 81 3d [0-48] 66 0f 13 05 ?? ?? ?? ?? 89 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_PVE_2147754942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.PVE!MTB"
        threat_id = "2147754942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 85 d8 f7 ff ff 8b 4d fc 89 78 04 5f 89 30 5e 33 cd 5b e8 ?? ?? ?? ?? 8b e5 5d c2 04 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_OY_2147755020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.OY!MTB"
        threat_id = "2147755020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d fc 03 cf 30 01 b8 01 00 00 00 83 f0 04 83 6d fc 01 39 75 fc 7d e3 5f 5e c9 c3}  //weight: 1, accuracy: High
        $x_1_2 = "SetProcessShutdownParameters" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_DEA_2147755455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.DEA!MTB"
        threat_id = "2147755455"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 ce 8d 5c 0b 1a 8b cb 2b ce 41 89 0d ?? ?? ?? ?? 69 f6 1d 53 00 00 03 f0 81 c2 ?? ?? ?? ?? 0f b7 fe 8b 74 24 10 89 16}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_MX_2147755845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.MX!MTB"
        threat_id = "2147755845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ca c1 e8 05 03 c5 89 4c 24 ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b 7c 24 ?? 81 3d ?? ?? ?? ?? bb 06 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_MX_2147755845_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.MX!MTB"
        threat_id = "2147755845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 a4 24 e0 00 00 00 8b 84 24 e0 00 00 00 81 84 24 ?? ?? ?? ?? f3 ae ac 68 81 ac 24 ?? ?? ?? ?? b3 30 c7 6b 81 84 24 ?? ?? ?? ?? 21 f4 7c 36 30 0c 1e 4e 0f 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_QR_2147756754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.QR!MTB"
        threat_id = "2147756754"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 e0 8b 45 f4 31 45 ec 8b 45 f4 31 45 e8 8b 45 f4 31 45 e4 8b 45 f4 31 45 e0 8b 45 e4 f7 6d ec f7 6d e8 03 45 f8 33 45 e0 89 45 f8 ff 45 f0 ff 4d d4 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_AA_2147756809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.AA!MTB"
        threat_id = "2147756809"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c8 03 7c 24 ?? 0f 57 c0 81 3d [0-48] c7 05 [0-48] 66 0f 13 05 [0-48] 89 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_AA_2147756809_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.AA!MTB"
        threat_id = "2147756809"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 00 88 45 ?? 8a 45 ?? 04 9f 2c 1a 73 ?? 80 6d ?? 20 a1 ?? ?? ?? ?? 8a 00 88 45 ?? 8a 45 ?? 04 9f 2c 1a 73 ?? 80 6d ?? 20 a1 ?? ?? ?? ?? 8a 00 88 45 ?? 8a 45 ?? 04 9f 2c 1a 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_AC_2147756811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.AC!MTB"
        threat_id = "2147756811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 57 c0 c1 e1 ?? 03 ca 66 0f 13 05 [0-32] 33 c8 81 3d [0-48] 89 4c 24 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_VC_2147756847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.VC!MTB"
        threat_id = "2147756847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f7 c7 05 [0-10] c1 ee ?? 03 c7 03 f1 0f 57 c0 8b cf 66 0f 13 05 ?? ?? ?? ?? c1 e1 ?? 03 ca 33 c8 81 3d [0-10] 89 4c 24 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_VC_2147756847_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.VC!MTB"
        threat_id = "2147756847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f 57 c0 66 0f 13 05 ?? ?? ?? ?? 8b 45 ?? 03 45 ?? 89 45 ?? 8b 4d ?? 33 4d ?? 89 4d ?? 8b 55 ?? 33 55 ?? 89 55 ?? 8b 45 ?? 2b 45 ?? 89 45}  //weight: 1, accuracy: Low
        $x_1_2 = {51 c7 45 fc ?? ?? ?? ?? 81 6d fc ?? ?? ?? ?? 2d f3 32 05 00 81 6d fc ?? ?? ?? ?? 81 45 fc ?? ?? ?? ?? 8b 45 fc 8b e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Danabot_PAA_2147773655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.PAA!MTB"
        threat_id = "2147773655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "62"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell -Executionpolicy bypass -File \"" wide //weight: 10
        $x_10_2 = "pipe\\mpr_pipe" wide //weight: 10
        $x_10_3 = "Windows Credentials" wide //weight: 10
        $x_10_4 = "nslookup.exe -type=any" wide //weight: 10
        $x_10_5 = "SELECT * FROM \"urls\"" ascii //weight: 10
        $x_10_6 = "SELECT * FROM cookies" ascii //weight: 10
        $x_1_7 = "wireshark" wide //weight: 1
        $x_1_8 = "SVCHOST.EXE" wide //weight: 1
        $x_1_9 = "HostName" wide //weight: 1
        $x_1_10 = "firewall" wide //weight: 1
        $x_1_11 = "encrypted_key" wide //weight: 1
        $x_1_12 = "test@test.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Danabot_GKM_2147778712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.GKM!MTB"
        threat_id = "2147778712"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 89 15 ?? ?? ?? ?? 85 c0 76 ?? 8b 3d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8a 94 31 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 88 14 31 3d 03 02 00 00 75 ?? 6a 00 6a 00 ff d7 a1 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 74 19 00 00 46 3b f0 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_RF_2147779624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.RF!MTB"
        threat_id = "2147779624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 39 74 24 ?? 7e ?? 53 8b 1d ?? ?? ?? ?? 55 8b 2d ?? ?? ?? ?? 57 8b 7c 24 ?? 8d 64 24 ?? 6a 00 ff d5 6a 00 ff d3 e8 ?? ?? ?? ?? 30 04 3e 6a 00 ff d3 6a}  //weight: 1, accuracy: Low
        $x_1_2 = {0f af 44 24 ?? c7 04 24 1b 3d 26 00 81 04 24 a8 61 00 00 8b 0c 24 8b 54 24 ?? 03 c8 89 0a 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_RTH_2147780469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.RTH!MTB"
        threat_id = "2147780469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "c:\\Prepare\\Control\\Work\\box\\heard.pdb" ascii //weight: 10
        $x_1_2 = "Client hook free failure." ascii //weight: 1
        $x_1_3 = "GetLocaleInfoEx" ascii //weight: 1
        $x_1_4 = "GetTickCount64" ascii //weight: 1
        $x_1_5 = "VirtualProtectEx" ascii //weight: 1
        $x_1_6 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_7 = "GetStartupInfoW" ascii //weight: 1
        $x_1_8 = "GetCPInfo" ascii //weight: 1
        $x_1_9 = "GetModuleHandleExW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Danabot_RPY_2147807210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.RPY!MTB"
        threat_id = "2147807210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 2e 64 6c 66 c7 05 ?? ?? ?? ?? 6c 00 c7 05 ?? ?? ?? ?? 6b 65 72 6e 66 c7 05 ?? ?? ?? ?? 65 6c c6 05 ?? ?? ?? ?? 33 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {6c 50 72 6f c7 05 ?? ?? ?? ?? 65 63 74 00 88 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 72 74 75 61 66 c7 05 ?? ?? ?? ?? 56 69 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_MBU_2147838383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.MBU!MTB"
        threat_id = "2147838383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 6c 76 72 2e 64 6c 6c 00 54 79 59 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_ND_2147896734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.ND!MTB"
        threat_id = "2147896734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {75 05 33 c0 89 46 0c 80 7e ?? ?? 75 1d e8 20 d5 ff ff 8b d8 85 db 74 12 8b c3 e8 5b e4 ff ff}  //weight: 5, accuracy: Low
        $x_1_2 = "IBX.IBStodedProc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_YAA_2147902997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.YAA!MTB"
        threat_id = "2147902997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "git7\\dll\\WndResizerApp.pdb" ascii //weight: 1
        $x_1_2 = "CIrNTzBaPkppGNf" ascii //weight: 1
        $x_1_3 = "CZnIUAAeJ" ascii //weight: 1
        $x_1_4 = "FxJWXdx" ascii //weight: 1
        $x_1_5 = "GbmgwMEzKpXc" ascii //weight: 1
        $x_1_6 = "HipXGmygXapBRYfa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_YAB_2147904057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.YAB!MTB"
        threat_id = "2147904057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 49 04 31 d2 31 4c 16 10 83 c2 04 39 c2 72 f5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_MBFW_2147905672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.MBFW!MTB"
        threat_id = "2147905672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 03 45 ?? 89 45 ?? 89 45 ?? 8d 04 33 33 d0 81 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d0 8b cf 89 55}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_MBFW_2147905672_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.MBFW!MTB"
        threat_id = "2147905672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 45 d0 89 45 ec 8b 45 f8 89 45 f0 8b 45 e8 01 45 fc 8b 45 fc 31 45 f0}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 f8 8b 55 f4 33 45 ec 81 c3 ?? ?? ?? ?? 8b 4d dc 2b f0 89 45 f8 89 75 fc 4f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_ADA_2147908896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.ADA!MTB"
        threat_id = "2147908896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 f7 f3 8b d0 6b c2 64 2b f8 8b c7 8b fa 83 ee 02 8b 04 85 d2 df 88 00 8b d6 03 d2 03 d1 89 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_GXQ_2147910062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.GXQ!MTB"
        threat_id = "2147910062"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 ?? 31 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 29 45 ?? 4b 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_MKV_2147913778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.MKV!MTB"
        threat_id = "2147913778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4a c1 e2 02 8b 1c 50 8b 45 f4 e8 ?? ?? ?? ?? 8b 55 f0 c1 e2 02 31 1c 50 ff 45 f0 ff 4d e4 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_ADAB_2147929727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.ADAB!MTB"
        threat_id = "2147929727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 00 1c 0f 51 ?? ?? ?? ?? ?? ?? 0f 51 00 ae 0f 51 00 ae 0f 51 00 c4 0f 51 00 ed 0f 51 00 80 0f 51 ?? ?? ?? ?? ?? ?? 0f 51 00 30 0f 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_BAA_2147934275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.BAA!MTB"
        threat_id = "2147934275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0d 09 59 08 1f 16 5d 59 20 00 01 00 00 58 20 00 01 00 00 5d d1 13 04 07 11 04 6f ?? 00 00 0a 26 08 17 58 0c 08 06 8e 69 32 c0}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_MXZ_2147934385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.MXZ!MTB"
        threat_id = "2147934385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c1 01 89 4d e4 8b 55 e4 3b 15 ?? ?? ?? ?? 7d 12 8b 45 e0 03 45 e4 8b 4d d8 03 4d e4 8a 11 88 10 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danabot_A_2147935985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danabot.A!MTB"
        threat_id = "2147935985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 89 e5 83 ec 14 52 57 56 31 c0 66 8c c9 80 f9 1b ?? ?? ?? ?? ?? ?? 8b 75 08 8b 7d 0c 8b 55 10 89 65 ec 83 e4 f0 6a 33 ?? ?? ?? ?? ?? 83 04 24 05}  //weight: 2, accuracy: Low
        $x_1_2 = "card_number_encrypted" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

