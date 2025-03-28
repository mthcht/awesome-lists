rule Trojan_Win32_Scar_A_2147629464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scar.A"
        threat_id = "2147629464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "44"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CallNextHookEx" ascii //weight: 1
        $x_1_2 = "RegisterHotKey" ascii //weight: 1
        $x_1_3 = "SendMessageA" ascii //weight: 1
        $x_1_4 = "#32770" ascii //weight: 1
        $x_1_5 = "Program Manager" ascii //weight: 1
        $x_10_6 = {00 6f 70 65 6e 00 65 78 70 6c 6f 72 65 72 2e 65 78 65}  //weight: 10, accuracy: High
        $x_10_7 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 10
        $x_10_8 = "\\usrinit.exe" wide //weight: 10
        $x_10_9 = {db e2 9b 0f 01 e0 a8 08 75 f9 0f 01 e0 a8 02 74 f9 68 ?? ?? 40 00 e8 ?? ?? 00 00 6b c0 02 8b c8 a0 ?? ?? 40 00 8d 3d ?? ?? 40 00 80 3f 00 74 02 30 07}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Scar_G_2147636676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scar.G"
        threat_id = "2147636676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 79 5f 77 6f 72 6b 65 72 5f 77 69 6e 64 6f 77 00}  //weight: 1, accuracy: High
        $x_1_2 = {65 78 65 2e 65 78 65 00 66 75 6e 63 31 00 66 75 6e 63 32 00 73 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 6a 00 68 00 04 00 00 (ff 35 ?? ?? ?? ?? e8 ?? ??|a1 ?? ?? ?? ?? 50 e8 ?? ?? 00 00 5f 5e 5b 8b) c2 10 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Scar_J_2147637780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scar.J"
        threat_id = "2147637780"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 00 6a 00 6a 00 68 00 00 00 80 6a 00 68 00 00 00 80 68 00 00 cf 00}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 08 83 f9 11 (0f 8e|7e) [0-4] 8b 85 ?? ?? ?? ?? 0f b6 08 83 e9 11 89 4d [0-4] 8b 95 02 83 c2 01}  //weight: 1, accuracy: Low
        $x_1_3 = "\\payload_loader_obfuscated\\" ascii //weight: 1
        $x_1_4 = {83 7d 14 01 75 ?? 68 ?? ?? ?? ?? 68 e8 03 00 00 6a 00 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 8d ac 00 00 00 8b 10 2b 11 8b 85 cc 00 00 00 89 10 8b 85 d8 00 00 00 8b 08 33 4d 2c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Scar_L_2147638416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scar.L"
        threat_id = "2147638416"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" ascii //weight: 10
        $x_10_2 = {26 76 65 72 73 69 6f 6e 3d 00 26 6f 73 3d}  //weight: 10, accuracy: High
        $x_3_3 = {6e 74 44 65 66 65 6e 64 65 72 00 63 66 6d 6d 6f 6e}  //weight: 3, accuracy: High
        $x_3_4 = {00 32 31 33 79 78 65 33 00}  //weight: 3, accuracy: High
        $x_1_5 = "/upload/gate.php" ascii //weight: 1
        $x_1_6 = "/upload/ip.php" ascii //weight: 1
        $x_1_7 = {73 6f 63 6b 73 35 00 64 64 6f 73 00}  //weight: 1, accuracy: High
        $x_1_8 = {5c 6d 73 75 70 64 61 74 65 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Scar_O_2147645118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scar.O"
        threat_id = "2147645118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".::.INFECT.::." wide //weight: 1
        $x_1_2 = "Computador....:" wide //weight: 1
        $x_1_3 = "MAC....:" wide //weight: 1
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 76 00 69 00 76 00 61 00 2e 00 69 00 73 00 2f 00 [0-32] 2f 00 67 00 61 00 6c 00 6c 00 65 00 72 00 79 00 2f 00 62 00 75 00 69 00 6c 00 64 00 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: Low
        $x_1_5 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 62 00 79 00 67 00 67 00 6a 00 61 00 2e 00 69 00 73 00 2f 00 70 00 68 00 70 00 2f 00 [0-48] 2f 00 68 00 65 00 6c 00 70 00 2e 00 74 00 78 00}  //weight: 1, accuracy: Low
        $x_1_6 = "system32\\drivers\\etc\\hosts" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Scar_Q_2147650871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scar.Q"
        threat_id = "2147650871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 0c 6b 00 00 bb 02 00 00 00 53 50 6a 00 e8 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {81 ec 00 22 00 00 89 65 fc b9 00 22 00 00 8b 7d fc fc f3 a4}  //weight: 1, accuracy: High
        $x_1_3 = {05 01 01 01 01 51 8a c8 d3 c0 59 51 8a c8 d3 c0 59}  //weight: 1, accuracy: High
        $x_1_4 = "Conclusion control" wide //weight: 1
        $x_1_5 = "Founded items:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Scar_R_2147651998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scar.R"
        threat_id = "2147651998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 4f 8b 45 f0 8a 8e ?? ?? ?? ?? 30 0c 18 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {83 78 14 10 59 72 02 8b 00 56 50 ff d3 50 ff 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ff ff 8b 45 c0 b9 4d 5a 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Scar_T_2147653628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scar.T"
        threat_id = "2147653628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c2 08 00 60 68 de c0 de 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? b8 aa 00 00 00 bb 02 00 00 00 53 50 6a 00 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? e8 ?? ?? ?? ?? 61 c3 55 8b ec 83 c4 ec}  //weight: 1, accuracy: Low
        $x_1_2 = {05 01 01 01 01 51 90 8a c8 90 d3 c0 90 59 90 eb 10}  //weight: 1, accuracy: Low
        $x_1_3 = {e2 bb 59 8b 1d ?? ?? 00 0d ac 90 32 c3 90 aa f7 c1 01 00 00 00 74}  //weight: 1, accuracy: Low
        $x_1_4 = "Shadowline variant" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Scar_U_2147655708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scar.U"
        threat_id = "2147655708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 b9 bd dd 0e 00 81 c1 15 01 00 00 8b 45 ?? d1 c0 c1 c8 06 85 c0 c1 c0 06 50 8f 45}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 00 24 00 00 8b 35 ?? ?? ?? ?? 81 c6 ca 01 00 00 8b fe 51 b9 d2 de 0e 00 8b 45 ?? d1 c0 89 45 ?? e2 f6 59 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {f3 a4 5e 56 33 c9 66 8b 4e 06 81 c6 f8 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {2b 55 08 8d 9b 88 00 00 00 8b 1b 33 c0 85 db 74 ?? 03 5d 08 83 3b 00 74 ?? 8b 33 8b 4b 04 83 e9 08 83 c3 08 0f b7 03 a9 00 30 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Scar_V_2147656875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scar.V"
        threat_id = "2147656875"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 64 6c 65 78 65 63 00 73 6f 63 6b 73 35 00}  //weight: 1, accuracy: High
        $x_1_2 = {c7 04 24 e0 93 04 00 b8 22 00 00 00 89 85 ?? ?? ff ff e8 ?? ?? ?? ?? ff 85 ?? ?? ff ff 83 ec 04 e9 ?? ?? ff ff 83 c5 18 8b 85 ?? ?? ff ff 8b 95 ?? ?? ff ff 83 f8 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Scar_AP_2147838113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scar.AP!MTB"
        threat_id = "2147838113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {19 4c ff 08 4c ff 0d ac 00 07 00 32 06 00 70 ff 68 ff 64 ff 29 06 00 74 ff 6c ff 4c ff 00 02 00 0d 04 50 ff 0a 08 00 04 00 35 50 ff 00 07}  //weight: 1, accuracy: High
        $x_1_2 = {2a 23 28 ff 1b 29 00 2a 23 24 ff 1b 26 00 2a 46 14 ff 0a 2a 00 08 00 74 0c ff 32 1c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Scar_EC_2147838538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scar.EC!MTB"
        threat_id = "2147838538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DucDung\\Desktop\\Pro" wide //weight: 1
        $x_1_2 = "HideFileExt" wide //weight: 1
        $x_1_3 = "Happy BirthDay My's Boss" wide //weight: 1
        $x_1_4 = "Sorry i don't want work for you in today" wide //weight: 1
        $x_1_5 = "quan trong" wide //weight: 1
        $x_1_6 = "url=file:file:file" wide //weight: 1
        $x_1_7 = "Image File Execution Options\\regedit.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Scar_RD_2147839882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scar.RD!MTB"
        threat_id = "2147839882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@del \"c:\\prog.bat\">nul" ascii //weight: 1
        $x_1_2 = "autorun.inf" ascii //weight: 1
        $x_1_3 = "RoB3rT" ascii //weight: 1
        $x_1_4 = "Informacje o systemie bot v.0.2" ascii //weight: 1
        $x_1_5 = "Keylogger started on chanel: %s" ascii //weight: 1
        $x_1_6 = "rox.wieczorniwymiatacze.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Scar_ABS_2147850826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scar.ABS!MTB"
        threat_id = "2147850826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "casino_extensions.exe" ascii //weight: 1
        $x_1_2 = "LiveMessageCenter.exe" ascii //weight: 1
        $x_1_3 = "casino_notifications.exe" ascii //weight: 1
        $x_1_4 = "hsmhzmrfvknhslktmtvhtwsrdrhphs_users.txt" ascii //weight: 1
        $x_1_5 = "\\Internet Explorer\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Scar_NS_2147900589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scar.NS!MTB"
        threat_id = "2147900589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 0c 40 8b 45 ?? 89 45 e4 8d 0c c8 6b c9 ?? 03 4d 18 6b c9 ?? 03 0d 48 95 40 00 4f}  //weight: 5, accuracy: Low
        $x_5_2 = {e8 8c 10 00 00 8b c3 8d 4b ff 69 c0 ?? ?? ?? ?? c1 f9 02 8b d6 89 75 f8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Scar_MA_2147901656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scar.MA!MTB"
        threat_id = "2147901656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii //weight: 1
        $x_1_2 = "shutdown -s -f -t 1" ascii //weight: 1
        $x_1_3 = "copy /y" ascii //weight: 1
        $x_1_4 = "Users\\ghigo\\source\\repos\\shutdown\\Release\\shutdown.pdb" ascii //weight: 1
        $x_1_5 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_6 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Scar_RC_2147905950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scar.RC!MTB"
        threat_id = "2147905950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5e 5b 31 db 8a 06 3c ff 75 02 ff e5 31 c0 51 50 31 c0}  //weight: 1, accuracy: High
        $x_1_2 = {31 c0 50 31 c0 31 c9 41 40 d3 e0 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Scar_EADV_2147936812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scar.EADV!MTB"
        threat_id = "2147936812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 45 fe 8b 4d 08 03 4d f0 0f b6 11 33 d0 8b 45 08 03 45 f0 88 10}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Scar_EAHH_2147936987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scar.EAHH!MTB"
        threat_id = "2147936987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {f7 75 10 8b 45 0c 0f b6 14 10 03 ca 8b c1 99 b9 64 00 00 00 f7 f9 89 55 f4 8b 55 08 03 55 f8 8a 02 88 45 ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

