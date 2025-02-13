rule Backdoor_Win32_Vawtrak_A_2147681339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Vawtrak.A"
        threat_id = "2147681339"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Vawtrak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 6a 1a 59 f7 f1 83 c2 61 66 89 14 7b 47 3b fe 72}  //weight: 1, accuracy: High
        $x_1_2 = {33 d2 6a 1a 59 f7 f1 80 c2 61 88 14 1f 47 3b fe 72}  //weight: 1, accuracy: High
        $x_1_3 = {80 38 3a 75 03 50 eb 18 8b 45 f8 ff b0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Vawtrak_A_2147681339_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Vawtrak.A"
        threat_id = "2147681339"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Vawtrak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b c8 8a 10 ff 4d 08 88 14 01 40 83 7d 08 00}  //weight: 2, accuracy: High
        $x_2_2 = {8b 01 69 c0 fd 43 03 00 05 c3 9e 26 00 89 01}  //weight: 2, accuracy: High
        $x_1_3 = "PID: %u [%0.2u:%0.2u:%0.2u]" ascii //weight: 1
        $x_1_4 = "[Socks] Failt connect BC [%s:%u]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Vawtrak_B_2147684228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Vawtrak.B"
        threat_id = "2147684228"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Vawtrak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 6a 1a 59 f7 f1 83 c2 61 66 89 14 7b 47 3b fe 72}  //weight: 1, accuracy: High
        $x_1_2 = {33 d2 6a 1a 59 f7 f1 80 c2 61 88 14 1f 47 3b fe 72}  //weight: 1, accuracy: High
        $x_1_3 = {8b 06 c6 85 ?? ?? ?? ?? 00 80 38 3a 8b 45 f8 ff b0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Vawtrak_C_2147685159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Vawtrak.C"
        threat_id = "2147685159"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Vawtrak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 03 59 33 d2 f7 f1 6a 00 5f 8b f2 83 c6 06 74}  //weight: 1, accuracy: High
        $x_1_2 = {81 3e 41 50 33 32 75 72 8b 46 08 83 c1 e8 3b c1 75 68 83 7e 10 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Vawtrak_C_2147685159_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Vawtrak.C"
        threat_id = "2147685159"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Vawtrak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 73 68 65 6c 6c 00 00 00 63 6f 6d 6d 61 6e 64 00 5c 6e 6f 74 65 70 61 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "PID: %u [%0.2u:%0.2u:%0.2u] " ascii //weight: 1
        $x_1_3 = {69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 00 00 00 00 66 00 69 00 72 00 65 00 66 00 6f 00 78 00 2e 00 65 00 78 00 65 00 00 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00 00 00 63 00 68 00 72 00 6f 00 6d 00 65 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "D:(A;OICI;GA;;;WD)" ascii //weight: 1
        $x_1_5 = {00 4d 69 6e 69 44 75 6d 70 57 72 69 74 65 44 75 6d 70 00 00 00 5c 25 75 2e 64 6d 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Vawtrak_D_2147686198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Vawtrak.D"
        threat_id = "2147686198"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Vawtrak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eval(function(p,a,c,k,e,r){" ascii //weight: 1
        $x_1_2 = "%s.pfx" ascii //weight: 1
        $x_1_3 = "&info=%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.4X%0.2X%0.4X&proxy=%s" ascii //weight: 1
        $x_1_4 = "././@LongLink" ascii //weight: 1
        $x_1_5 = "/post.aspx?messageID=%u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Vawtrak_D_2147686540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Vawtrak.gen!D"
        threat_id = "2147686540"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Vawtrak"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2f 62 76 70 6d 61 67 69 63 00}  //weight: 10, accuracy: High
        $x_10_2 = {75 73 65 72 5f 69 64 25 00 00 00 00 76 65 72 73 69 6f 6e 5f 69 64 25 00 66 72 61 6d 65 77 6f 72 6b 5f 6b 65 79 25 00}  //weight: 10, accuracy: High
        $x_10_3 = "sync|ScreenShot|encodeURIComponent|LogAdd|UpdateConfig|StartSocks" ascii //weight: 10
        $x_1_4 = {00 5b 42 43 5d 20 43 6d 64 20}  //weight: 1, accuracy: High
        $x_1_5 = {49 6e 69 74 20 69 6e 20 53 68 65 6c 6c 20 3d 20 25 75 00}  //weight: 1, accuracy: High
        $x_1_6 = {49 6e 69 74 20 69 6e 20 42 72 6f 77 73 65 72 20 3d 20 25 75 00}  //weight: 1, accuracy: High
        $x_1_7 = {5b 50 6f 6e 79 5d 20 46 61 69 6c 20 47 65 74 20 50 61 73 73 0d 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Vawtrak_D_2147686674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Vawtrak.gen!D!!Vawtrak.gen!D"
        threat_id = "2147686674"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Vawtrak"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "Vawtrak: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "D: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2f 62 76 70 6d 61 67 69 63 00}  //weight: 10, accuracy: High
        $x_10_2 = {75 73 65 72 5f 69 64 25 00 00 00 00 76 65 72 73 69 6f 6e 5f 69 64 25 00 66 72 61 6d 65 77 6f 72 6b 5f 6b 65 79 25 00}  //weight: 10, accuracy: High
        $x_10_3 = "sync|ScreenShot|encodeURIComponent|LogAdd|UpdateConfig|StartSocks" ascii //weight: 10
        $x_1_4 = {00 5b 42 43 5d 20 43 6d 64 20}  //weight: 1, accuracy: High
        $x_1_5 = {49 6e 69 74 20 69 6e 20 53 68 65 6c 6c 20 3d 20 25 75 00}  //weight: 1, accuracy: High
        $x_1_6 = {49 6e 69 74 20 69 6e 20 42 72 6f 77 73 65 72 20 3d 20 25 75 00}  //weight: 1, accuracy: High
        $x_1_7 = {5b 50 6f 6e 79 5d 20 46 61 69 6c 20 47 65 74 20 50 61 73 73 0d 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Vawtrak_D_2147686674_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Vawtrak.gen!D!!Vawtrak.gen!D"
        threat_id = "2147686674"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Vawtrak"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "Vawtrak: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "D: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/bpmagic" ascii //weight: 1
        $x_1_2 = {76 65 72 73 69 6f 6e 5f 69 64 25 00 72 61 6e 64 6f 6d 25 00 66 72 61 6d 65 77 6f 72 6b 5f 6b 65 79 25}  //weight: 1, accuracy: High
        $x_1_3 = "|GetServer|random|new|PostServer|" ascii //weight: 1
        $x_1_4 = "|StartSocks|StartVnc|SendForm|StartVideo|" ascii //weight: 1
        $x_1_5 = "|document|location|href|StopVideo|ExecVBS|" ascii //weight: 1
        $x_1_6 = "%s.Hide('%0.8X%0.8X')" ascii //weight: 1
        $x_2_7 = "info=%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.4X%0.2X%0.4X&proxy=%s&name=%ws&domain=%ws" ascii //weight: 2
        $x_2_8 = "id=%0.8X%0.8X%0.8X%0.4X%0.4X%0.4X&iv=%0.8X&av=%0.8X&uptime=%u" ascii //weight: 2
        $x_1_9 = {5b 50 6f 6e 79 5d 20 46 61 69 6c 20 47 65 74 20 50 61 73 73 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_10 = "DL_EXEC Status [Pipe]: %u-%u-%u-%u" ascii //weight: 1
        $x_1_11 = "Start Socks Status[Pipe]: %u-%u-%u" ascii //weight: 1
        $x_1_12 = "Start VNC Status[Pipe]: %u-%u-%u" ascii //weight: 1
        $x_1_13 = {42 4f 54 5f 49 44 3a 00 50 52 4f 4a 45 43 54 5f 49 44 3a 00 42 55 49 4c 44 3a}  //weight: 1, accuracy: High
        $x_1_14 = "[BC] Wait Ping error %u[%u]" ascii //weight: 1
        $x_1_15 = "[BC] Cmd need reauth" ascii //weight: 1
        $x_1_16 = "[VDESK] Read CMD %u[%u]" ascii //weight: 1
        $x_1_17 = "[VDESK] NOT AUTH CMD %u" ascii //weight: 1
        $x_1_18 = "[VNC] CmdLine = %s" ascii //weight: 1
        $x_1_19 = "[VNC] CreateProcess Status = %u (%u)" ascii //weight: 1
        $x_1_20 = "PID: %u [%0.2u:%0.2u:%0.2u]" ascii //weight: 1
        $x_2_21 = {c7 06 41 50 33 32 50 8d 45 fc 50 53 56 e8 ?? ?? ?? ?? 83 c4 10 85 c0 74 12 8b 45 fc 81 38 45 43 46 47}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Vawtrak_F_2147688092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Vawtrak.F"
        threat_id = "2147688092"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Vawtrak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "{%0.4X%0.4X-%0.4X-%0.4X-%0.4X-%0.4X%0.4X%0.4X}" ascii //weight: 4
        $x_2_2 = {8b 7c 24 14 8b f7 2b f5 8d 64 24 00 8a 1f 84 db 74 20 8b cd 8b d6 8d 9b 00 00 00 00 3a 1a 74 06 49 42 85 c9 75 f6 83 c0 07 85 c9 75 08 83 c0 02 eb 03 83 c0 07 47 46 83 6c 24 1c 01 75 ce}  //weight: 2, accuracy: High
        $x_1_3 = "aeiou" ascii //weight: 1
        $x_1_4 = {53 3a 28 4d 4c 3b 3b 4e 57 3b 3b 3b 4c 57 29 [0-4] 44 3a 28 41 3b 4f 49 43 49 3b 47 41 3b 3b 3b 57 44 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Vawtrak_X_2147696867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Vawtrak.X"
        threat_id = "2147696867"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Vawtrak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "103"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "https://%s.%s/favicon.ico" ascii //weight: 100
        $x_1_2 = "#domain" ascii //weight: 1
        $x_1_3 = "#botid" ascii //weight: 1
        $x_1_4 = "#cfgload" ascii //weight: 1
        $x_1_5 = "#dbgmsg" ascii //weight: 1
        $x_1_6 = "#delfile" ascii //weight: 1
        $x_1_7 = "sol_low/" ascii //weight: 1
        $x_1_8 = "framework_key%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Vawtrak_X_2147696867_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Vawtrak.X"
        threat_id = "2147696867"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Vawtrak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "id=%0.8X%0.8X%0.8X%0.4X%0.4X%0.4X&iv=%0.8X&av=%0.8X&uptime=%u" ascii //weight: 1
        $x_1_2 = "&info=%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.4X%0.2X%0.4X&proxy=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Vawtrak_X_2147696867_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Vawtrak.X"
        threat_id = "2147696867"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Vawtrak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\temp" wide //weight: 1
        $x_1_2 = "~%0.8x.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Vawtrak_O_2147707514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Vawtrak.O"
        threat_id = "2147707514"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Vawtrak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 04 01 6d 4e c6 41 05 39 30 00 00 6a 04 59 6b c9 00}  //weight: 1, accuracy: High
        $x_1_2 = {32 84 3e 0a 02 00 00 88 44 2e ff 46 59 83 fe 40 72 e4}  //weight: 1, accuracy: High
        $x_1_3 = {8b 54 24 18 80 3a 4d 75 06 80 7a 01 5a 74 21}  //weight: 1, accuracy: High
        $x_1_4 = {eb 1d 6a 3a 50 ff 15 ?? ?? ?? ?? 85 c0 74 ef 8d 4d fc 51 ff d0}  //weight: 1, accuracy: Low
        $x_1_5 = "regsvr32.exe /s /i:\"%s\" \"%s" ascii //weight: 1
        $x_1_6 = "PID: %u [%0.2u:%0.2u:%0.2u]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Vawtrak_AVW_2147843549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Vawtrak.AVW!MTB"
        threat_id = "2147843549"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Vawtrak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a c7 83 f2 06 0f 8d ?? ?? ?? ?? 5d 00 59 ff d5 69 d3 d2 ff eb 23 ec 28 00 65 00 00 81 ad ?? ?? ?? ?? ?? ?? ?? ?? e0 23 d6 03 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

