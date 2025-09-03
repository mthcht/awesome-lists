rule Trojan_Win64_Mikey_SIB_2147807424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.SIB!MTB"
        threat_id = "2147807424"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "ServiceMain" ascii //weight: 10
        $x_10_2 = "svchost.exe" wide //weight: 10
        $x_10_3 = "rundll32.exe" wide //weight: 10
        $x_1_4 = {45 33 c9 43 8a 3c 11 49 ff c1 4d 3b c8 7d ?? 43 8a 34 11 49 ff c1 eb ?? 41 bc ?? ?? ?? ?? 4d 3b c8 7d ?? 43 8a 2c 11 49 ff c1 eb ?? bb ?? ?? ?? ?? 44 8a f7 40 80 e7 ?? 40 8a c6 c0 e8 ?? 40 c0 e7 ?? 40 8a ce 40 0a f8 80 e1 ?? 40 8a c5 c0 e8 ?? c0 e1 ?? 41 c0 ee ?? 0a c8 40 8a c5 24 ?? 45 85 e4 74 ?? b1 ?? eb ?? 0f b6 d0 85 db b8 ?? ?? ?? ?? 0f 45 d0 41 0f b6 c6 4c 8d 35 ?? ?? ?? ?? 0f b6 c9 42 8a 04 30 41 83 c3 04 41 88 45 ?? 40 0f b6 c7 49 83 c5 ?? 42 8a 04 30 41 88 45 ?? 42 8a 0c 31 41 88 4d ?? 0f b6 ca ba ?? ?? ?? ?? 42 8a 0c 31 41 88 4d ?? 4d 3b c8 0f 8c}  //weight: 1, accuracy: Low
        $x_1_5 = {48 8b f2 4c 8b f9 4d 63 f0 48 8d 2d ?? ?? ?? ?? 44 8b ef 43 0f b6 54 3d ?? 48 8b cd ff 15 ?? ?? ?? ?? 43 0f b6 54 3d ?? 48 8b cd 48 8b d8 40 2a dd ff 15 ?? ?? ?? ?? 43 0f b6 54 3d ?? 4c 8b e0 48 8b cd 44 2a e5 ff 15 ?? ?? ?? ?? 43 0f b6 54 3d ?? 48 8b e8 48 8d 05 ?? ?? ?? ?? 48 8b c8 40 2a e8 ff 15 ?? ?? ?? ?? c0 e3 ?? 40 8a cd 4c 8b d8 48 8d 05 ?? ?? ?? ?? c0 e1 06 44 2a d8 41 8a c4 49 83 c5 ?? c0 e8 ?? 41 0a cb ff c7 0a c3 88 06 48 ff c6 40 80 fd ?? 74 ?? 40 c0 ed ?? 41 c0 e4 ?? ff c7 41 0a ec 40 88 2e 48 ff c6 41 80 fb ?? 74 ?? 88 0e ff c7 48 ff c6 48 8d 2d ?? ?? ?? ?? 4d 3b ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Mikey_AMBC_2147898723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.AMBC!MTB"
        threat_id = "2147898723"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 39 c7 74 ?? 8a 4c 05 d0 41 30 4c 05 00 48 ff c0 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_AMCD_2147898994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.AMCD!MTB"
        threat_id = "2147898994"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8d 0c 30 41 ff c0 80 34 39 ?? 44 3b c0 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_CCFM_2147899647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.CCFM!MTB"
        threat_id = "2147899647"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {21 c9 89 8c 24 ?? ?? ?? ?? 4c 89 5c 24 50 66 8b 44 24 1e 66 83 f0 ff 66 89 84 24 ?? ?? ?? ?? 4c 89 b4 24 ?? ?? ?? ?? 8b 4c 24 20 69 c9 ?? ?? ?? ?? 89 8c 24 ?? ?? ?? ?? 4d 39 c3 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_NM_2147903218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.NM!MTB"
        threat_id = "2147903218"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 84 24 a0 00 00 00 48 8b d9 48 89 4c 24 20 48 8d 05 16 a9 10 00 48 89 44 24 40 48 c7 44 24 48 12 00 00 00 45 33 c0 48 8d 54 24 40 48 8d 4c 24 60 e8 66 ea fe ff 90 48 8d 8c 24 80 00 00 00 e8 08 87 00 00 90 4c 8d 44 24 60 48 8b d0}  //weight: 2, accuracy: High
        $x_1_2 = {48 8d 8c 24 80 00 00 00 e8 b9 53 00 00 90 48 8d 4c 24 60 e8 ae 53 00 00 48 8b c3 eb 05}  //weight: 1, accuracy: High
        $x_1_3 = "_decrypt_payments.txt" ascii //weight: 1
        $x_1_4 = "KillBrowserProcesses" ascii //weight: 1
        $x_1_5 = "_decrypt_cookies.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_HNS_2147905331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.HNS!MTB"
        threat_id = "2147905331"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4e 00 61 00 6d 00 65 00 00 00 00 00 4c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00 00 00 00 00 3a 00 09 00 01 00 46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 4c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00}  //weight: 2, accuracy: High
        $x_2_2 = "C:\\Users\\mpx16\\source\\repos\\Launcher\\bin\\Release\\net8.0\\win-x64\\native\\Launcher.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_AMI_2147907010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.AMI!MTB"
        threat_id = "2147907010"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b df eb 38 48 8d 15 f3 a5 00 00 48 8b cb ff 15 9a 1e 00 00 48 85 c0 74 e6 48 8d 15 f6 a5 00 00 48 89 05 27 fb 00 00 48 8b cb ff 15 7e 1e 00 00 48 85 c0 74 ca}  //weight: 2, accuracy: High
        $x_2_2 = {ff 48 85 d2 7e 24 49 2b f6 4b 8b 8c eb 50 69 02 00 49 03 ce 42 8a 04 36 42 88 44 f9 3e ff c7 49 ff c6 48 63 c7 48 3b c2}  //weight: 2, accuracy: High
        $x_1_3 = "node_modules\\windo32lib\\build\\Release\\windo32lib.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_AMY_2147907962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.AMY!MTB"
        threat_id = "2147907962"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8b 4d df 89 45 d7 4d 85 c9 4c 89 75 ff 48 8d 45 e7 89 75 f7 48 89 44 24 30 4c 8d 45 d7 4d 0f 44 c7 44 89 7c 24 28 45 33 c9 4c 89 7c 24 20 33 d2 48 8d 4d f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_CCHW_2147909905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.CCHW!MTB"
        threat_id = "2147909905"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4c 0f 44 c5 89 6c 24 28 45 33 c9 48 89 6c 24 20 33 d2 48 8d 4c 24 60 ff 15}  //weight: 5, accuracy: High
        $x_5_2 = {8b 54 24 40 4c 8b cf 44 8b c6 48 8b cb ff 15}  //weight: 5, accuracy: High
        $x_1_3 = "modules\\win32crypted\\src\\win32decrypt" ascii //weight: 1
        $x_1_4 = "modules\\windo32lib\\src\\windo32lib" ascii //weight: 1
        $x_1_5 = "modules\\maximumpswd\\src\\maximumpswd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Mikey_NB_2147915263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.NB!MTB"
        threat_id = "2147915263"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 7d 00 00 0f 95 c0 88 07 b0 01 48 8b 4d 08 48 33 cd e8}  //weight: 10, accuracy: High
        $x_1_2 = "C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell" ascii //weight: 1
        $x_1_3 = "$BlockedFromReflection" ascii //weight: 1
        $x_1_4 = "$disable regedit" ascii //weight: 1
        $x_1_5 = "$disable uac" ascii //weight: 1
        $x_1_6 = "$start with windows" ascii //weight: 1
        $x_1_7 = "hentai" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_GMN_2147921671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.GMN!MTB"
        threat_id = "2147921671"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0a 59 b8 a4 42 30 f3 8a cb 5e 85 0a 24 a2 1a ef b7 20}  //weight: 5, accuracy: High
        $x_5_2 = {f6 03 1d 8f 41 5b 5a 91 33 50 10}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_GMT_2147921673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.GMT!MTB"
        threat_id = "2147921673"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {21 4e 95 8c 62 45 03 87 ?? ?? ?? ?? 32 fd 2d}  //weight: 5, accuracy: Low
        $x_5_2 = {8e 04 73 19 a4 74 ?? ?? ?? ?? d0 31 2e e7 6d e2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_MKV_2147921732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.MKV!MTB"
        threat_id = "2147921732"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 89 f1 4c 6b d2 50 4c 01 d0 48 83 c0 40 44 33 18 44 89 de 89 f0 4c 03 8c 24 b0 00 00 00 89 4c 24 44 4c 89 c9 48 89 54 24 38 4c 89 c2 49 89 c0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_ASJ_2147922823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.ASJ!MTB"
        threat_id = "2147922823"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {48 8b c8 ff 15 ?? ?? ?? ?? 45 33 c9 4c 89 64 24 28 4c 8d 05 ?? ?? ?? ?? 44 89 64 24 20 33 d2 33 c9 ff 15 ?? ?? ?? ?? 48 85 c0 75 1d 48 8d ?? ?? ?? ?? 00 4c 8b a4 24 a8 00 00 00 48 83 c4 70 41 5f 41 5e 5d e9 ?? ?? ?? ?? ba ff ff ff ff 48 8b c8 ff 15}  //weight: 4, accuracy: Low
        $x_1_2 = "ServiceMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_NE_2147923487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.NE!MTB"
        threat_id = "2147923487"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "start cmd /C \"COLOR C && echo. Outdated version, contact fael#2081 && TIMEOUT 10 > nul" ascii //weight: 2
        $x_1_2 = "xxxx?xxxx????xxx" ascii //weight: 1
        $x_1_3 = "----------------%ld%s" ascii //weight: 1
        $x_1_4 = "security.dll" ascii //weight: 1
        $x_1_5 = "DecryptMessage" ascii //weight: 1
        $x_1_6 = "C:\\Windows\\KsDumperDriver.sys" ascii //weight: 1
        $x_1_7 = "AppData\\Local\\dnSpy" ascii //weight: 1
        $x_1_8 = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs" ascii //weight: 1
        $x_1_9 = "\\examples\\Exe\\" ascii //weight: 1
        $x_1_10 = "netsh advfirewall firewall add rule name" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_GZT_2147925149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.GZT!MTB"
        threat_id = "2147925149"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5b 59 8b d1 32 fd 24}  //weight: 5, accuracy: High
        $x_5_2 = {14 1c 34 39 10 b0 ?? ?? ?? ?? 31 74 9a ?? 59 ?? ?? ?? ?? 54 5e f6 ed}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_GTZ_2147925895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.GTZ!MTB"
        threat_id = "2147925895"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f3 8b ec 60 97 30 68 ?? 63 fb 1c 61 0c ce 00 e1 e2 ?? 6a 85 30 00}  //weight: 10, accuracy: Low
        $x_10_2 = {30 24 73 1c f6 2b 31 03 f1 31 1f 09 d7 92 ?? fe 64 bc ?? ?? ?? ?? 21 cb 20 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Mikey_GTK_2147927354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.GTK!MTB"
        threat_id = "2147927354"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d3 e2 30 9e ?? ?? ?? ?? a3 ?? ?? ?? ?? ?? ?? ?? ?? d2 d0 54 a3 ?? ?? ?? ?? ?? ?? ?? ?? 6a d0 54 a3}  //weight: 5, accuracy: Low
        $x_5_2 = {f7 d1 c1 c9 ?? 44 31 4c 54 ?? 41 ff c9 ff c9 f7 d9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_GTN_2147927474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.GTN!MTB"
        threat_id = "2147927474"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 e8 1a ee 29 3e c0 29 38}  //weight: 5, accuracy: High
        $x_5_2 = {88 29 30 11 0c e8 f3 0b a8 ?? ?? ?? ?? 2a 51 01 08 7e fe 02 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_GTS_2147927526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.GTS!MTB"
        threat_id = "2147927526"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {91 6b 94 c2 ?? ?? ?? ?? 21 89 e7 30 a7 ?? ?? ?? ?? 12 d0 5a f7 0c 31 ?? ?? ?? ?? 30 2c 41 3a 42}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_GZN_2147927960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.GZN!MTB"
        threat_id = "2147927960"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4c 26 8b 34 df 63 41 ?? ?? bd ?? ?? ?? ?? 6d 44 21 6f ?? 86 5d ?? 32 4c c3 ?? 30 28 32 ec 08 52 ?? 54 5a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_GVT_2147928357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.GVT!MTB"
        threat_id = "2147928357"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8e 1f 1b 74 e2 dc 8a 3f 28 26 3e 32 f9 13 ca}  //weight: 5, accuracy: High
        $x_5_2 = {34 0d 89 50 ed 53 31 b0 a6 ba}  //weight: 5, accuracy: High
        $x_10_3 = {12 73 fd 33 58 a9 32 7f 54 5a 46 f3 c0 3a 65 f3 31 48 e6 49 66 38 22 92}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Mikey_GCN_2147928626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.GCN!MTB"
        threat_id = "2147928626"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 d0 0f be c2 6b d0 ?? 0f b6 c1 02 c0 ff c1 41 2a d0 80 c2 ?? 02 d0 41 30 51 ?? 83 f9}  //weight: 10, accuracy: Low
        $x_10_2 = {9f a4 2b d7 7d 27 2e d6 9f a4 2f d7 5a 27 2e d6 17 5f 2f d7 55 27 2e d6 5c 27 2f d6 a5 27 2e d6 4f a3 27 d7 5d 27 2e d6 4f a3 d1 d6 5d 27 2e d6 4f a3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Mikey_NIT_2147929715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.NIT!MTB"
        threat_id = "2147929715"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 57 08 48 03 dd 44 8b 47 04 48 8b cb 48 03 d0 e8 ?? ?? 1a 00 89 5f fc 49 8b 06 ff c6 48 83 c7 28 0f b7 48 06 3b f1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_NFA_2147933512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.NFA!MTB"
        threat_id = "2147933512"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "etPropWriteInt" ascii //weight: 2
        $x_1_2 = {48 8d 6c 24 b9 48 81 ec c0 00 00 00 48 8b 05 b9 b8 01 00 48 33 c4 48 89 45 3f 4c 8b f1 83 fa 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_GNN_2147935234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.GNN!MTB"
        threat_id = "2147935234"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 ed 69 83 ?? ?? ?? ?? 50 ed 06 83 54 ec 6f 83 55 ?? 18 82 54 ec 24 fb 55 ed}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_MZL_2147942170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.MZL!MTB"
        threat_id = "2147942170"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {44 89 c9 83 f1 ff 81 e1 1e a6 7f 9b 41 ba ff ff ff ff 41 81 f2 1e a6 7f 9b 45 21 d1 44 89 c2 83 f2 ff 81 e2 1e a6 7f 9b 45 21 d0 44 09 c9 44 09 c2 31 d1 88 08 e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_AKV_2147943413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.AKV!MTB"
        threat_id = "2147943413"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4c 8b d2 45 33 c9 4c 2b d1 4c 8b c1 b8 a1 a0 a0 a0 41 f7 e1 c1 ea 05 0f be c2 6b c8 33 41 8a c1 41 ff c1 2a c1 04 32 43 32 04 10 41 88 00 49 ff c0 41 83 f9 0d 7c d5}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_HMZ_2147945518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.HMZ!MTB"
        threat_id = "2147945518"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {44 89 e7 4c 8b a4 24 ?? ?? ?? ?? 41 30 04 24 49 ff c4 4c 89 a4 24 ?? ?? ?? ?? 4c 3b a4 24 58 01 00 00 48 b8 aa a2 91 e3 af 8c 39 12 4d 89 fc 49 89 d7 48 ba 83 8e 8e dd af 8c 39 12 48 0f 44 c2 4c 89 fa 4d 89 e7 41 89 fc 48 89 cf e9 ba}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_AHC_2147945647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.AHC!MTB"
        threat_id = "2147945647"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4f 24 49 03 cb 42 0f b7 14 51 8b 4f 1c 49 03 cb 8b 04 91 48 8d 15 28 ff ff ff 49 8b 0e 49 03 c3 ff d0}  //weight: 2, accuracy: High
        $x_3_2 = {38 8b 4e 24 49 03 cb 42 0f b7 14 51 8b 4e 1c 49 03 cb 8b 04 91 49 03 c3 48 8d}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_LMB_2147946480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.LMB!MTB"
        threat_id = "2147946480"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {8b 7c 24 24 83 c9 ff 33 c0 8b f7 f2 ae f7 d1 49 6a 01 8b e9 8d 4c 24 18 55}  //weight: 15, accuracy: High
        $x_10_2 = {8b 44 24 10 8b 54 24 38 8b c8 c1 e9 10 89 0a 8b 4c 24 3c 25 ff ff 00 00 89 01}  //weight: 10, accuracy: High
        $x_5_3 = {8b 44 24 08 81 ec 28 06 00 00 53 8b d9 56 57 8b 73 08 8b 7b 04 8b 53 0c 8b c8 46 03 fa 8b d1 89 73 08 8b b4 24 38 06 00 00 c1 e9 02 f3 a5 8b ca 83 e1 03}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_LMC_2147946634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.LMC!MTB"
        threat_id = "2147946634"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {4c 8b 40 30 4c 89 85 18 02 00 00 49 63 40 3c 4a 8b 8c 00 88 00 00 00 44 8b c9 48 89 8d 78 02 00 00 4d 03 c8 4c 89 8d 20 02 00 00 48 c1 e9 20 89 8d 10 02 00 00 4d 3b c8}  //weight: 20, accuracy: High
        $x_10_2 = {0f be c8 41 33 c8 44 69 c1 43 01 00 00 0f b6 02 48 8d 52 01 84 c0}  //weight: 10, accuracy: High
        $x_5_3 = {4c 89 9d c0 00 00 00 49 8b db 48 89 9d c8 00 00 00 49 8b c3 4c 8b 40 30 4c 89 45 68 49 63 40 3c 4a 8b 8c 00 88 00 00 00 44 8b d1 48 89 4d 10 4d 03 d0 4c 89 55 70 48 c1 e9 20 89 4d 60 4d 3b d0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_SXA_2147946827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.SXA!MTB"
        threat_id = "2147946827"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {44 0f b7 00 66 45 85 c0 74 27 66 44 89 01 44 0f b7 40 02 66 45 85 c0 74 18 66 44 89 41 02 48 83 c0 04 48 83 c1 04 83 c2 02 81 fa 04 01 00 00 7c cf}  //weight: 3, accuracy: High
        $x_2_2 = {8b c1 99 2b c2 d1 f8 ff c8 4c 8b c6 41 80 fb 2d 41 0f 94 c0 48 63 d8 4c 3b c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_LMF_2147948447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.LMF!MTB"
        threat_id = "2147948447"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 44 24 74 89 44 24 60 65 48 8b 04 25 58 00 00 00 41 8b c9 41 ba 98 12 00 00 48 8b 14 c8 b9 a0 12 00 00 8b 04 11 a8 01}  //weight: 10, accuracy: High
        $x_20_2 = {48 b8 fb 82 e4 08 c1 3b e9 c5 48 89 44 24 30 48 8b 44 24 30 48 89 4c 24 30 49 8d 4b 98 48 89 44 24 50 48 8b 44 24 30 c5 fe 6f 44 24 60 48 89 44 24 58 c5 fd ef 4c 24 40}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_LMG_2147948756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.LMG!MTB"
        threat_id = "2147948756"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {66 89 84 24 a6 01 00 00 c6 84 24 a8 01 00 00 88 c6 84 24 a9 01 00 00 95 c6 84 24 aa 01 00 00 7d c6 84 24 ab 01 00 00 86 c6 84 24 ac 01 00 00 7d c6 84 24 ad 01 00 00 d3 c6 84 24 ae 01 00 00 67 c6 84 24 af 01 00 00 5b}  //weight: 20, accuracy: High
        $x_10_2 = {66 89 84 24 a6 00 00 00 c6 84 24 a8 00 00 00 91 c6 84 24 a9 00 00 00 40 c6 84 24 aa 00 00 00 28 c6 84 24 ab 00 00 00 97 c6 84 24 ac 00 00 00 c7 c6 84 24 ad 00 00 00 c6 c6 84 24 ae 00 00 00 97 c6 84 24 af 00 00 00 67}  //weight: 10, accuracy: High
        $x_3_3 = "[+] Decrypted AES Key (hex)" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_SXB_2147949265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.SXB!MTB"
        threat_id = "2147949265"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 c7 83 90 00 00 00 00 00 00 00 48 c7 83 98 00 00 00 08 00 00 00 48 c7 83 a0 00 00 00 00 00 00 00 c6 83 03 01 00 00 01 c6 83 01 01 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = "src\\modules\\browser\\injection\\injector.rs" ascii //weight: 1
        $x_1_3 = "src\\modules\\browser\\crypto\\decrypt.rs" ascii //weight: 1
        $x_1_4 = "--wallet-download" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_PCW_2147950022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.PCW!MTB"
        threat_id = "2147950022"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "netsh advfirewall firewall add rule name" ascii //weight: 1
        $x_1_2 = "schannel: failed to decrypt data, need more data" ascii //weight: 1
        $x_1_3 = "EMOTE / AVATAR HACK ( ON . OFF )" ascii //weight: 1
        $x_1_4 = "MAHON FREE VRS.pdb" ascii //weight: 1
        $x_1_5 = "CAMERA HACK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_AR_2147951148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.AR!MTB"
        threat_id = "2147951148"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b 94 24 80 01 00 00 48 8d 4c 24 5c e8 ?? ?? ?? ?? ?? ?? ?? ?? 44 8b 44 24 38 33 d2 b9 01 00 00 00 ff 15 ?? ?? ?? ?? 48 89 44 24 28 48 83 7c 24 28 00 74 ?? 33 d2 48 8b 4c 24 28}  //weight: 10, accuracy: Low
        $x_8_2 = {c7 84 24 ec 00 00 00 88 13 00 00 48 8d 84 24 88 00 00 00 48 8b f8 33 c0 b9 ?? ?? ?? ?? f3 aa c7 84 24 88 00 00 ?? ?? ?? ?? 00 c7 84 24 a0 00 00 00 03 00 00 00 48 8d 84 24 d8 00 00 00}  //weight: 8, accuracy: Low
        $x_7_3 = "wms temp.exe" ascii //weight: 7
        $x_15_4 = "C:\\miner_log.txt" ascii //weight: 15
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_SXC_2147951251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.SXC!MTB"
        threat_id = "2147951251"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 89 45 00 48 8b 45 00 48 89 45 38 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 66 0f 6f 55 30 48 89 45 00 48 8b 45 00 48 89 45 40}  //weight: 3, accuracy: Low
        $x_2_2 = {48 8d 45 20 f3 0f 7f 85 90 00 00 00 48 0f 47 45 20 44 88 a5 80 00 00 00 44 88 20 48 8d 84 24 98 01 00 00 48 8b 38}  //weight: 2, accuracy: High
        $x_1_3 = {48 8d 54 24 70 4c 89 6c 24 30 4c 89 6c 24 28 45 33 c9 48 89 54 24 20 41 b8 ?? ?? ?? ?? 41 8b 56 10 ff d0 8b 7c 24 70 4d 89 2f 4d 89 6f 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

