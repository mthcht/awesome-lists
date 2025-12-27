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

