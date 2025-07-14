rule Trojan_Win32_CobaltStrike_PA_2147747969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.PA!MTB"
        threat_id = "2147747969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 d2 83 ec ?? 39 da 7d ?? 89 d1 8b 75 10 83 e1 03 8a 0c 0e 8b 75 08 32 0c 16 88 0c 10 42 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_PA_2147747969_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.PA!MTB"
        threat_id = "2147747969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c0 89 85 ?? ?? 00 00 8b 45 04 39 85 ?? ?? 00 00 7d 22 48 63 85 ?? ?? 00 00 0f b6 84 05 ?? 00 00 00 83 f0 0a 48 63 8d ?? ?? 00 00 88 84 0d ?? 00 00 00 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "\\cobaltstrike 3.14\\payload\\AvByPass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_SK_2147753756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.SK!MTB"
        threat_id = "2147753756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/F /Create /TN Tencentid /sc minute /MO 1 /TR C:\\Users\\Public\\Music\\tencentsoso.exe" ascii //weight: 1
        $x_5_2 = "C:\\Users\\Public\\Music\\cia.plan" ascii //weight: 5
        $x_1_3 = "C:\\Users\\Public\\Music\\SideBar.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_SK_2147753756_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.SK!MTB"
        threat_id = "2147753756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 31 46 48 8b 46 ?? 83 f0 ?? 01 46 ?? 8b 46 ?? 2d ?? ?? ?? ?? 31 86 ?? ?? ?? ?? b8 ?? ?? ?? ?? 2b 46 ?? 01 86 ?? ?? ?? ?? 8b 8e ?? ?? ?? ?? 8b 46}  //weight: 1, accuracy: Low
        $x_1_2 = "RegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_2147759292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike!MTB"
        threat_id = "2147759292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "artifact64big.dll" ascii //weight: 1
        $x_1_2 = "artifact32big.dll" ascii //weight: 1
        $x_1_3 = "gkernel32.dll" wide //weight: 1
        $x_1_4 = "K[ZKK\\OKM" ascii //weight: 1
        $x_1_5 = "CreateThread" ascii //weight: 1
        $x_1_6 = "GetProcAddress" ascii //weight: 1
        $x_1_7 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_8 = "GetCurrentProcess" ascii //weight: 1
        $x_1_9 = "GetCommandLineA" ascii //weight: 1
        $x_1_10 = "GetCommandLineW" ascii //weight: 1
        $x_1_11 = "CreateFileW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Trojan_Win32_CobaltStrike_CK_2147762935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.CK!MTB"
        threat_id = "2147762935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 d8 7d 17 8b 75 ?? 89 c1 83 e1 ?? 8a 0c 0e 8b 75 08 32 0c 06 88 0c 02 40 eb e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_ZZ_2147771660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.ZZ!MTB"
        threat_id = "2147771660"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 0f b6 c0 41 83 c0 01 b8 ?? ?? ?? ?? 41 f7 e8 41 03 d0 c1 fa 09 8b c2 c1 e8 1f 03 d0 69 d2 ?? ?? 00 00 44 2b c2 41 0f b6 f8 42 0f b6 0c 1f 41 0f b6 c1 03 c8 b8 00 f7 e9 03 d1 c1 fa 09 8b c2 c1 e8 1f 03 d0 69 d2 01 00 00 44 8b c9 44 2b ca 41 0f b6 d1 42 0f b6 0c 1f 42 0f b6 04 1a 42 88 04 1f 42 88 0c 1a 0f b6 c9 42 0f b6 04 1f 03 c8 b8 00 f7 e9 03 d1 c1 fa 09 8b c2 c1 e8 1f 03 d0 69 d2 01 00 00 2b ca 8b 05 ?? ?? ?? ?? f7 d8 48 63 d0 49 03 d4 0f b6 c1 42 0f b6 0c 18 42 30 0c 3a 49 83 c4 01 48 83 eb 01 74 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_SS_2147771876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.SS!MTB"
        threat_id = "2147771876"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c8 bf 04 00 00 00 99 f7 ff 8b 7d 10 8a 04 17 8b 7d 08 32 04 0f 88 04 0b 41 39 f1 7c e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_AC_2147773407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.AC!MTB"
        threat_id = "2147773407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c9 83 f8 0e 0f 45 c8 8a 81 8c 62 08 10 30 04 32 42 8d 41 01 3b d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_AC_2147773407_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.AC!MTB"
        threat_id = "2147773407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Microsoft Base Cryptographic Provider v1.0" ascii //weight: 3
        $x_3_2 = "LibTomMath" ascii //weight: 3
        $x_3_3 = "InternetQueryDataAvailable" ascii //weight: 3
        $x_3_4 = "HttpAddRequestHeadersA" ascii //weight: 3
        $x_3_5 = "beacon.dll" ascii //weight: 3
        $x_3_6 = "ReflectiveLoader@4" ascii //weight: 3
        $x_3_7 = "round-truth-58c8" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147773441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 5b 89 df 52 45 55 89 e5 81 c3 ?? ?? ?? ?? ff d3 68 f0 b5 a2 56 68 04 00 00 00 57 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 30 00 00 57 6a 00 ff 75 08 ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 ?? 8d 45 fc 50 57 ff 75 f8 56 ff 75 08 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147773441_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 52 55 48 89 e5 48 81 ec 20 00 00 00 48 8d 1d ea ff ff ff 48 89 df 48 81 c3 ?? ?? ?? ?? ff d3 41 b8 ?? ?? ?? ?? 68 04 00 00 00 5a 48 89 f9 ff d0 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {41 b9 00 30 00 00 4d 8b c7 33 d2 48 8b cf c7 44 24 20 40 00 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147773441_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fc 48 83 e4 f0 e8 c8 00 00 00 41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a}  //weight: 1, accuracy: High
        $x_1_2 = {e9 4f ff ff ff 5d 6a 00 49 be 77 69 6e 69 6e 65 74 00 41 56 49 89 e6 4c 89 f1 41 ba 4c 77 26 07 ff d5 48 31 c9 48 31 d2 4d 31 c0 4d 31 c9 41 50 41 50 41 ba 3a 56 79 a7 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147773441_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff e0 58 5f 5a 8b 12 eb 86 5b 80 7e 10 00 75 3b c6 46 10 01 68 a6 95 bd 9d ff d3 3c 06 7c 1a}  //weight: 1, accuracy: High
        $x_1_2 = {31 c9 51 51 ff 76 08 ff 36 51 51 68 38 68 0d 16 ff d3 c9}  //weight: 1, accuracy: High
        $x_1_3 = {e8 00 00 00 00 58 83 c0 25 83 ec 08 89 e2 c7 42 04 33 00 00 00 89 02 e8 09 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {48 31 d2 48 8b 0e 41 ba c8 38 a4 40 ff d5 48 85 c0 74 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147773441_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 00 10 00 00 4c 8d 87 80 00 00 00 48 89 d6 c7 44 24 20 04 00 00 00 31 d2 ff 15 ?? ?? ?? ?? 48 89 c5 48 8d 44 24 50 4d 89 e0 49 89 f9 48 89 ea 48 89 d9 48 89 44 24 20 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 48 65 00 00 00 c7 44 24 40 70 00 00 00 c7 44 24 38 69 00 00 00 c7 44 24 30 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147773441_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 4a 0d ce 09 e8}  //weight: 1, accuracy: High
        $x_1_2 = {68 d0 03 5c 09 e8}  //weight: 1, accuracy: High
        $x_1_3 = {68 f4 15 93 b0 e8}  //weight: 1, accuracy: High
        $x_1_4 = {68 31 74 bc 7f e8}  //weight: 1, accuracy: High
        $x_1_5 = {68 b0 06 6a 90 e8}  //weight: 1, accuracy: High
        $x_1_6 = {68 9c b8 ba a6 57 e8}  //weight: 1, accuracy: High
        $x_1_7 = {68 78 5c 3b 55 e8}  //weight: 1, accuracy: High
        $x_1_8 = {68 65 41 fb a7 e8}  //weight: 1, accuracy: High
        $x_1_9 = {6a 40 68 00 30 00 00 8b 46 50 50 8b 46 34 50 ff d7}  //weight: 1, accuracy: High
        $x_1_10 = {25 61 70 70 64 61 74 61 25 5c 46 6c 61 73 68 50 6c 61 79 65 72 00 [0-8] 5c 70 6c 75 67 31 2e 64 61 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147773441_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b8 00 30 00 00 31 c9 48 89 f7 ff 15 ?? ?? ?? ?? 48 89 c3 31 c0 39 f8 7d 16 48 89 c2 83 e2 03 41 8a 14 14 32 54 05 00 88 14 03 48 ff c0 eb e6}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 48 65 00 00 00 c7 44 24 40 70 00 00 00 c7 44 24 38 69 00 00 00 c7 44 24 30 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {b9 60 ea 00 00 ff d3 eb f7 [0-16] 48 ff e1}  //weight: 1, accuracy: Low
        $x_1_4 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147773441_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 04 00 00 00 48 63 f2 49 89 cc 89 d7 4c 89 c5 48 89 f2 41 b8 00 30 00 00 31 c9 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {41 b8 20 00 00 00 ff 15 ?? ?? ?? ?? 4c 8d ?? ?? ?? ?? ?? 49 89 d9 31 d2 31 c9 48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 48 65 00 00 00 c7 44 24 40 70 00 00 00 c7 44 24 38 69 00 00 00 c7 44 24 30 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147773441_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 01 6a 02 e8 [0-48] 6a 02 58 ff 75 08 66 89 45 ec e8 [0-64] 6a 78 56 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8e 4e 0e ec 74 ?? 81 7d ?? aa fc 0d 7c 74 ?? 81 7d ?? 54 ca af 91 74}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 40 16 25 00 80 00 00 74 09 c7 45 f0 40 00 00 00 eb 07 c7 45 f0 04 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {ff 75 f0 68 00 30 00 00 8b 45 f4 ff 70 50 6a 00 ff 55}  //weight: 1, accuracy: High
        $x_1_5 = {83 7d 9c 40 73 19 0f b6 45 a7 8b 4d 98 03 4d 9c 0f b6 09 33 c8 8b 45 98 03 45 9c 88 08 eb da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147773441_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5d 08 c7 44 24 10 04 00 00 00 c7 44 24 0c 00 10 00 00 8d 87 80 00 00 00 89 44 24 08 c7 44 24 04 00 00 00 00 89 1c 24 ff 15 ?? ?? ?? ?? 83 ec 14 89 c6 8d 45 e0 89 44 24 10 8b 45 1c 89 7c 24 0c 89 74 24 04 89 1c 24 89 44 24 08 ff 15 ?? ?? ?? ?? 8b 45 e0 83 ec 14 39 f8 75}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 24 65 00 00 00 c7 44 24 20 70 00 00 00 c7 44 24 1c 69 00 00 00 c7 44 24 18 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147773441_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f9 8e 4e 0e ec 74 ?? 81 f9 aa fc 0d 7c 74 ?? 81 f9 54 ca af 91 74}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 45 16 66 23 c1 66 f7 d8 b8 00 40 00 00 45 1b e4 41 83 e4 3c 41 83 c4 04 44 89 64 24 20 66 85 45 16}  //weight: 1, accuracy: High
        $x_1_3 = {ff d6 45 33 db 48 85 db 75 21 8b 55 50 45 8b cc 33 c9 41 b8 00 30 00 00 41 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {b9 40 00 00 00 48 03 f3 48 8b c5 f3 a4 b9 40 00 00 00 44 30 00 49 03 c5 49 2b cd}  //weight: 1, accuracy: High
        $x_1_5 = {48 b8 73 79 73 74 65 6d 33 32 48 83 cb ff 48 89 07 4c 8b c3 49 ff c0 42 80 7c 07 09 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147773441_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 5a e8 00 00 00 00 5b 89 df 52 45 55 89 e5 81 c3 ?? ?? 00 00 ff d3 68 f0 b5 a2 56 68 04 00 00 00 57 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {8e 4e 0e ec 74 ?? 81 7d ?? aa fc 0d 7c 74 ?? 81 7d ?? 54 ca af 91 74}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 40 16 25 00 80 00 00 74 09 c7 45 f0 40 00 00 00 eb 07 c7 45 f0 04 00 00 00 83 65 c0 00}  //weight: 1, accuracy: High
        $x_1_4 = {ff 75 f0 68 00 30 00 00 8b 45 f4 ff 70 50 6a 00 ff 55}  //weight: 1, accuracy: High
        $x_1_5 = {83 7d 9c 40 73 19 0f b6 45 a7 8b 4d 98 03 4d 9c 0f b6 09 33 c8 8b 45 98 03 45 9c 88 08 eb da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147773441_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 0c c7 44 24 0c 04 00 00 00 c7 44 24 08 00 30 00 00 c7 04 24 00 00 00 00 89 74 24 04 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {c7 44 24 08 20 00 00 00 ff 15 ?? ?? ?? ?? 83 ec 10 89 5c 24 0c c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 08 ?? ?? ?? ?? c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 24 65 00 00 00 c7 44 24 20 70 00 00 00 c7 44 24 1c 69 00 00 00 c7 44 24 18 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147773441_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 ff e1 41 54 55 57 56 53 48 83 ec 40 41 b9 04 00 00 00 48 63 f2 48 89 cd [0-21] 41 b8 00 30 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8d 4c 24 3c 48 89 f2 48 89 d9 41 b8 20 00 00 00 ff 15 ?? ?? ?? ?? 4c 8d ?? ?? ff ff ff 49 89 d9 31 d2 31 c9 48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 ff 15 ?? ?? ?? ?? 90 48 83 c4 40}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 48 65 00 00 00 c7 44 24 40 70 00 00 00 c7 44 24 38 69 00 00 00 c7 44 24 30 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147773441_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 00 00 00 00 58 83 c0 25 83 ec 08 89 e2 c7 42 04 33 00 00 00 89 02 e8 09 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {f0 e8 c8 00 00 00 41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a}  //weight: 1, accuracy: High
        $x_1_3 = {48 31 d2 48 8b 0e 41 ba c8 38 a4 40 ff d5 48 85 c0 74 0c}  //weight: 1, accuracy: High
        $n_100_4 = {4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 64 00 65 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 68 00 65 00 6c 00 70 00 65 00 72 00 00 00}  //weight: -100, accuracy: High
        $n_100_5 = {4f 00 75 00 74 00 62 00 79 00 74 00 65 00 20 00 50 00 43 00 20 00 52 00 65 00 70 00 61 00 69 00 72 00 00 00}  //weight: -100, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147773441_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 8b 45 08 5d ff e0 55 89 e5 [0-32] c7 44 24 0c 04 00 00 00 c7 44 24 08 00 30 00 00 c7 04 24 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 08 20 00 00 00 89 44 24 0c ff 15 ?? ?? ?? ?? 83 ec 10 89 ?? 24 0c c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 08 ?? ?? ?? ?? c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 24 65 00 00 00 c7 44 24 20 70 00 00 00 c7 44 24 1c 69 00 00 00 c7 44 24 18 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147773441_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "could not run command (w/ token) because of its length of %d bytes!" ascii //weight: 1
        $x_1_2 = "could not spawn %s (token): %d" ascii //weight: 1
        $x_1_3 = "I'm already in SMB mode" ascii //weight: 1
        $x_1_4 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147773441_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 5a 41 52 55 48 89 e5 48 81 ec 20 00 00 00 48 8d 1d ea ff ff ff 48 89 df 48 81 c3 ?? ?? ?? ?? ff d3 41 b8 f0 b5 a2 56 68 04 00 00 00 5a 48 89 f9 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {81 f9 8e 4e 0e ec 74 ?? 81 f9 aa fc 0d 7c 74 ?? 81 f9 54 ca af 91 74}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 45 16 66 23 c1 66 f7 d8 b8 00 40 00 00 45 1b e4 41 83 e4 3c 41 83 c4 04 44 89 64 24 20 66 85 45 16}  //weight: 1, accuracy: High
        $x_1_4 = {ff d6 45 33 db 48 85 db 75 21 8b 55 50 45 8b cc 33 c9 41 b8 00 30 00 00 41 ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {b9 40 00 00 00 48 03 f3 48 8b c5 f3 a4 b9 40 00 00 00 44 30 00 49 03 c5 49 2b cd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147773441_18
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "42"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 f9 5b bc 4a 6a 74}  //weight: 10, accuracy: High
        $x_10_2 = {8e 4e 0e ec 74 ?? 81 ?? aa fc 0d 7c 74 ?? 81 ?? 54 ca af 91}  //weight: 10, accuracy: Low
        $x_10_3 = {3c 33 c9 41 b8 00 30 00 00 4c 03 ?? 44 8d 49 40 41 8b}  //weight: 10, accuracy: Low
        $x_10_4 = "ReflectiveLoader" ascii //weight: 10
        $x_1_5 = "\\\\.\\pipe\\sshagent" ascii //weight: 1
        $x_1_6 = {63 6f 6e 6e 65 63 74 20 74 6f 20 25 73 3a 25 64 20 66 61 69 6c 65 64 3a 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_7 = "COBALTSTRIKE" ascii //weight: 1
        $x_1_8 = "%1024[^ ] %8[^:]://%1016[^/]%7168" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CobaltStrike_A_2147773441_19
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "42"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {75 b1 81 7d ?? 5b bc 4a 6a 75 0b}  //weight: 10, accuracy: Low
        $x_10_2 = {8e 4e 0e ec 74 ?? 81 7d ?? aa fc 0d 7c 74 ?? 81 7d ?? 54 ca af 91}  //weight: 10, accuracy: Low
        $x_10_3 = {6a 40 68 00 30 00 00 8b ?? ?? 8b ?? ?? ?? 6a 00 ff 55}  //weight: 10, accuracy: Low
        $x_10_4 = "ReflectiveLoader" ascii //weight: 10
        $x_1_5 = "\\\\.\\pipe\\sshagent" ascii //weight: 1
        $x_1_6 = {63 6f 6e 6e 65 63 74 20 74 6f 20 25 73 3a 25 64 20 66 61 69 6c 65 64 3a 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_7 = "COBALTSTRIKE" ascii //weight: 1
        $x_1_8 = "%1024[^ ] %8[^:]://%1016[^/]%7168" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CobaltStrike_A_2147773441_20
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 4e 0e ec 74 ?? 81 7d ?? aa fc 0d 7c 74 ?? 81 7d ?? 54 ca af 91 74}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 40 16 25 00 80 00 00 74 09 c7 45 f0 40 00 00 00 eb 07 c7 45 f0 04 00 00 00 83 65 c0 00}  //weight: 1, accuracy: High
        $x_1_3 = {ff 75 f0 68 00 30 00 00 8b 45 f4 ff 70 50 6a 00 ff 55}  //weight: 1, accuracy: High
        $x_1_4 = {83 7d 9c 40 73 19 0f b6 45 a7 8b 4d 98 03 4d 9c 0f b6 09 33 c8 8b 45 98 03 45 9c 88 08 eb da}  //weight: 1, accuracy: High
        $x_1_5 = {83 c4 10 33 c0 80 b0 ?? ?? ?? ?? 69 40 3d 00 10 00 00 7c f1 68 00 10 00 00 b9 ?? ?? ?? ?? 8d 44 24 14 e8}  //weight: 1, accuracy: Low
        $x_1_6 = {62 65 61 63 6f 6e [0-4] 2e 64 6c 6c 00}  //weight: 1, accuracy: Low
        $x_1_7 = "ReflectiveLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147773441_21
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f9 8e 4e 0e ec 74 ?? 81 f9 aa fc 0d 7c 74 ?? 81 f9 54 ca af 91 74}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 45 16 66 23 c1 66 f7 d8 b8 00 40 00 00 45 1b e4 41 83 e4 3c 41 83 c4 04 44 89 64 24 20 66 85 45 16}  //weight: 1, accuracy: High
        $x_1_3 = {ff d6 45 33 db 48 85 db 75 21 8b 55 50 45 8b cc 33 c9 41 b8 00 30 00 00 41 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {b9 40 00 00 00 48 03 f3 48 8b c5 f3 a4 b9 40 00 00 00 44 30 00 49 03 c5 49 2b cd}  //weight: 1, accuracy: High
        $x_1_5 = {41 8b c7 80 34 28 69 48 ff c0 48 3d 00 10 00 00 7c f1 48 8d 4c 24 20 41 b8 00 10 00 00 48 8b d5 e8}  //weight: 1, accuracy: High
        $x_1_6 = {62 65 61 63 6f 6e [0-4] 2e 64 6c 6c 00}  //weight: 1, accuracy: Low
        $x_1_7 = "ReflectiveLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147773441_22
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fc e8 89 00 00 00 60 89 e5 31 d2 64 8b 52 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26}  //weight: 1, accuracy: High
        $x_1_2 = {eb 86 5d 68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5 31 ff 57 57 57 57 57 68 3a 56 79 a7 ff d5}  //weight: 1, accuracy: High
        $x_1_3 = {eb 86 5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 50 [0-8] 50 68 ea 0f df e0 ff d5}  //weight: 1, accuracy: Low
        $x_1_4 = {eb 86 5d 31 c0 6a 40 b4 10 68 00 10 00 00 68 ff ff 07 00 6a 00 68 58 a4 53 e5 ff d5 83 c0 40 89 c7 50 31 c0 b0 70 b4 69 50 68 64 6e 73 61 54 68 4c 77 26 07 ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {68 58 a4 53 e5 ff d5 50 e9 a8 00 00 00 5a 31 c9 51 51 68 00 b0 04 00 68 00 b0 04 00 6a 01 6a 06 6a 03 52 68 45 70 df d4 ff d5 50 8b 14 24 6a 00 52 68 28 6f 7d e2 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147773441_23
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "62"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 f9 8e 4e 0e ec 74 ?? 81 f9 aa fc 0d 7c 74 ?? 81 f9 54 ca af 91 74}  //weight: 10, accuracy: Low
        $x_10_2 = {0f b7 45 16 66 23 c1 66 f7 d8 b8 00 40 00 00 45 1b e4 41 83 e4 3c 41 83 c4 04 44 89 64 24 20 66 85 45 16}  //weight: 10, accuracy: High
        $x_10_3 = {ff d6 45 33 db 48 85 db 75 21 8b 55 50 45 8b cc 33 c9 41 b8 00 30 00 00 41 ff d5}  //weight: 10, accuracy: High
        $x_10_4 = {b9 40 00 00 00 48 03 f3 48 8b c5 f3 a4 b9 40 00 00 00 44 30 00 49 03 c5 49 2b cd}  //weight: 10, accuracy: High
        $x_10_5 = {41 8b c7 80 34 28 69 48 ff c0 48 3d 00 10 00 00 7c f1 48 8d 4c 24 20 41 b8 00 10 00 00 48 8b d5 e8}  //weight: 10, accuracy: High
        $x_10_6 = "ReflectiveLoader" ascii //weight: 10
        $x_1_7 = {57 6f 77 36 34 44 69 73 61 62 6c 65 57 6f 77 36 34 46 73 52 65 64 69 72 65 63 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_8 = {53 74 61 72 74 65 64 20 73 65 72 76 69 63 65 20 25 73 20 6f 6e 20 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147773441_24
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "52"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5b bc 4a 6a 0f 85 ?? 00 00 00 8b}  //weight: 10, accuracy: Low
        $x_10_2 = {8e 4e 0e ec 74 [0-3] aa fc 0d 7c 74 [0-3] 54 ca af 91 75}  //weight: 10, accuracy: Low
        $x_10_3 = {b8 0a 4c 53 75}  //weight: 10, accuracy: High
        $x_10_4 = {68 00 30 00 00 0a 00 6a 40 10 00 8b ?? 3c}  //weight: 10, accuracy: Low
        $x_10_5 = "ReflectiveLoader" ascii //weight: 10
        $x_1_6 = "\\\\.\\pipe\\bypassuac" ascii //weight: 1
        $x_1_7 = "\\System32\\cliconfg.exe" wide //weight: 1
        $x_1_8 = "[-] ICorRuntimeHost::GetDefaultDomain" ascii //weight: 1
        $x_1_9 = "[-] Invoke_3 " ascii //weight: 1
        $x_1_10 = {74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00 00 00 72 00 75 00 6e 00 61 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {43 6f 6e 73 65 6e 74 50 72 6f 6d 70 74 42 65 68 61 76 69 6f 72 41 64 6d 69 6e 00}  //weight: 1, accuracy: High
        $x_1_12 = "\\\\.\\pipe\\keylogger" ascii //weight: 1
        $x_1_13 = "[unknown: %02X]" ascii //weight: 1
        $x_1_14 = {2f 73 65 6e 64 25 73 00 50 4f 53 54}  //weight: 1, accuracy: High
        $x_1_15 = {72 63 61 70 3a 2f 2f 00 45 72 72 6f 72}  //weight: 1, accuracy: High
        $x_1_16 = "\\\\.\\pipe\\netview" ascii //weight: 1
        $x_1_17 = " %-22s %-20s %-14s %s" ascii //weight: 1
        $x_1_18 = "\\\\.\\pipe\\powershell" ascii //weight: 1
        $x_1_19 = "ICLRRuntimeInfo::IsLoadable" ascii //weight: 1
        $x_1_20 = "\\\\.\\pipe\\screenshot" ascii //weight: 1
        $x_1_21 = {00 4a 50 45 47 4d 45 4d 00}  //weight: 1, accuracy: High
        $x_1_22 = "\\\\.\\pipe\\elevate" ascii //weight: 1
        $x_1_23 = "[*] %s loaded in userspace" ascii //weight: 1
        $x_1_24 = "\\\\.\\pipe\\hashdump" ascii //weight: 1
        $x_1_25 = "Global\\SAM" ascii //weight: 1
        $x_1_26 = "\\\\.\\pipe\\portscan" ascii //weight: 1
        $x_1_27 = {5c 5c 25 73 5c 69 70 63 24 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 22 of ($x_1_*))) or
            ((4 of ($x_10_*) and 12 of ($x_1_*))) or
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CobaltStrike_A_2147773441_25
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A"
        threat_id = "2147773441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "52"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 f9 5b bc 4a 6a 0f 85 ?? 00 00 00 49}  //weight: 10, accuracy: Low
        $x_10_2 = {81 f9 8e 4e 0e ec 74 ?? 81 f9 aa fc 0d 7c 74 ?? 81 f9 54 ca af 91}  //weight: 10, accuracy: Low
        $x_10_3 = {b8 0a 4c 53 75}  //weight: 10, accuracy: High
        $x_10_4 = {48 63 5f 3c 33 c9 41 b8 00 30 00 00 48 03 df 44 8d 49 40 8b 53 50 41 ff d6}  //weight: 10, accuracy: High
        $x_10_5 = "ReflectiveLoader" ascii //weight: 10
        $x_1_6 = "\\\\.\\pipe\\bypassuac" ascii //weight: 1
        $x_1_7 = "\\System32\\cliconfg.exe" wide //weight: 1
        $x_1_8 = "[-] ICorRuntimeHost::GetDefaultDomain" ascii //weight: 1
        $x_1_9 = "[-] Invoke_3 " ascii //weight: 1
        $x_1_10 = {74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00 00 00 72 00 75 00 6e 00 61 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {43 6f 6e 73 65 6e 74 50 72 6f 6d 70 74 42 65 68 61 76 69 6f 72 41 64 6d 69 6e 00}  //weight: 1, accuracy: High
        $x_1_12 = "\\\\.\\pipe\\keylogger" ascii //weight: 1
        $x_1_13 = "[unknown: %02X]" ascii //weight: 1
        $x_1_14 = {2f 73 65 6e 64 25 73 00 50 4f 53 54}  //weight: 1, accuracy: High
        $x_1_15 = {72 63 61 70 3a 2f 2f 00 45 72 72 6f 72}  //weight: 1, accuracy: High
        $x_1_16 = "\\\\.\\pipe\\netview" ascii //weight: 1
        $x_1_17 = " %-22s %-20s %-14s %s" ascii //weight: 1
        $x_1_18 = "\\\\.\\pipe\\powershell" ascii //weight: 1
        $x_1_19 = "ICLRRuntimeInfo::IsLoadable" ascii //weight: 1
        $x_1_20 = "\\\\.\\pipe\\screenshot" ascii //weight: 1
        $x_1_21 = {00 4a 50 45 47 4d 45 4d 00}  //weight: 1, accuracy: High
        $x_1_22 = "\\\\.\\pipe\\mimikatz" ascii //weight: 1
        $x_1_23 = "token::elevate" ascii //weight: 1
        $x_1_24 = "\\\\.\\pipe\\hashdump" ascii //weight: 1
        $x_1_25 = "Global\\SAM" ascii //weight: 1
        $x_1_26 = "\\\\.\\pipe\\elevate" ascii //weight: 1
        $x_1_27 = "[*] %s loaded in userspace" ascii //weight: 1
        $x_1_28 = "\\\\.\\pipe\\portscan" ascii //weight: 1
        $x_1_29 = {5c 5c 25 73 5c 69 70 63 24 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 22 of ($x_1_*))) or
            ((4 of ($x_10_*) and 12 of ($x_1_*))) or
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CobaltStrike_J_2147775469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.J!ibt"
        threat_id = "2147775469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {74 65 73 74 2e 64 6c 6c 00 74 6f 6d 6d 79}  //weight: 3, accuracy: High
        $x_3_2 = "shellcodeexecute" ascii //weight: 3
        $x_3_3 = {6a 40 68 00 10 00 00 68 ?? ?? ?? ?? 6a 00 ff 15}  //weight: 3, accuracy: Low
        $x_1_4 = {8b c6 8b 7d fc 99 f7 fb 8a 04 97 30 04 0e 46 3b 75 0c 7c ec}  //weight: 1, accuracy: High
        $x_1_5 = {45 fc 99 f7 7d 0c ?? ?? ?? 33 0c 90 01 01 55 10 03 55 fc 88 0a eb cf}  //weight: 1, accuracy: Low
        $x_1_6 = "kuwKXRILHuYiNDE4h11LhmITcVx0DIOs5krbsAotLeJdYN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CobaltStrike_MA_2147776625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.MA!MTB"
        threat_id = "2147776625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 83 c0 01 89 45 fc 83 7d fc ?? 73 14 8b 4d fc 0f be 54 0d e0 83 f2 44 8b 45 fc 88 54 05 e0 eb dd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_MA_2147776625_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.MA!MTB"
        threat_id = "2147776625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff 77 04 ff d6 59 85 c0 59 0f 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 77 04 ff d6 59 85 c0 59 0f 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 77 04 ff d6 59 85 c0 59 0f 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 77 04 ff d6 59 85 c0 59 0f 84}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_MA_2147776625_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.MA!MTB"
        threat_id = "2147776625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "43.138.30.76" wide //weight: 3
        $x_3_2 = "/logging.bin" wide //weight: 3
        $x_2_3 = {83 bc 24 88 00 00 00 08 8d 4c 24 74 6a 00 0f 43 4c 24 78 6a 50 51 50 ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_MA_2147776625_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.MA!MTB"
        threat_id = "2147776625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 4a 01 89 08 8b 4c 90 [0-1] 89 ca c1 ea [0-1] 23 90 [0-2] 00 00 31 ca 89 d0 c1 e0 [0-1] 25 [0-4] 31 d0 89 c1 c1 e1 [0-1] 81 e1 [0-4] 31 c1 89 c8 c1 e8 [0-1] 31 c8}  //weight: 1, accuracy: Low
        $x_1_2 = "broken pipe" ascii //weight: 1
        $x_1_3 = "connection aborted" ascii //weight: 1
        $x_1_4 = "owner dead" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_CM_2147776798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.CM!MTB"
        threat_id = "2147776798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f0 83 c1 ?? 89 4d ?? 8b 55 ?? 3b 55 ?? 73 ?? 8b 45 ?? 25 ?? ?? ?? ?? 79 ?? 48 0d ?? ?? ?? ?? 40 88 45 ?? 0f b6 4d ?? 8b 55 ?? 03 55 ?? 0f be 02 33 c1 8b 4d ?? 03 4d ?? 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_CM_2147776798_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.CM!MTB"
        threat_id = "2147776798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 a1 f2 0a 4a 00 66 0f af c7 66 a3 [0-4] a1 [0-4] 0f af c7 69 c0 [0-4] 66 a3 [0-4] 0f b7 c0 0f af c1 03 c7 a3 [0-4] 2b d3 2b d5 5f 83 ea [0-1] 5d 0f b7 c2 5b 59 c3}  //weight: 1, accuracy: Low
        $x_1_2 = "inch" wide //weight: 1
        $x_1_3 = "broken pipe" ascii //weight: 1
        $x_1_4 = "owner dead" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_SD_2147777400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.SD!MTB"
        threat_id = "2147777400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "could not run command (w/ token) because of its length of %d bytes!" ascii //weight: 1
        $x_1_2 = "could not spawn %s (token): %d" ascii //weight: 1
        $x_1_3 = "I'm already in SMB mode" ascii //weight: 1
        $x_1_4 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" ascii //weight: 1
        $n_10_5 = "Threat_Sonar" wide //weight: -10
        $n_10_6 = {73 6f 6e 61 72 5f 6c 65 76 65 6c [0-4] 6d 61 6c 77 61 72 65 5f 66 61 6d 69 6c 79}  //weight: -10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_E_2147782694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.E!ibt"
        threat_id = "2147782694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "fA]Z" ascii //weight: 1
        $x_1_2 = "YG@JG\\" ascii //weight: 1
        $x_1_3 = "]W]@OZGXK" ascii //weight: 1
        $x_1_4 = {4d 5a 52 45 e8 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {8e 4e 0e ec 74 ?? 81 ?? ?? aa fc 0d 7c 74 ?? 81 ?? ?? 54 ca af 91 74 ?? 81 ?? ?? 1b c6 46 79 74 ?? 81 ?? ?? fc a4 53 07 74 ?? 81 ?? ?? 04 49 32 d3 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_MZK_2147783108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.MZK!MTB"
        threat_id = "2147783108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 d8 7d 17 89 c2 8b 4d [0-1] 83 e2 [0-1] 8a 14 11 8b 4d [0-1] 32 14 01 88 14 06 40 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_AS_2147784791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.AS!MTB"
        threat_id = "2147784791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {03 48 3c 89 4d b0 8b 45 b0 83 20 00 33 c0 8b 4d fc 66 89 01 8b 45 fc 83 60 3c 00}  //weight: 10, accuracy: High
        $x_10_2 = {32 c0 8b 49 50 f3 aa 8b 45 f4 8b 40 50 8b 4d c0 8d 44 01 c0 89 45 98 8b 45 f4 8a 40 10 88 45}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_DA_2147794109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.DA!MTB"
        threat_id = "2147794109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d9 83 e3 03 8a 1c 3b 8d 14 29 32 1c 10 41 3b ce 88 1a 7c ?? 8b 54 24 18 8b 44 24 1c 5b 89 2a 5f 89 30}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c8 8a 4c 39 04 8b d0 83 e2 03 32 4c 14 14 40 3b c6 88 4c 18 ff 7c 06 00 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_DB_2147794110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.DB!MTB"
        threat_id = "2147794110"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\.\\pipe\\Vmware.0000000000.0002" ascii //weight: 1
        $x_1_2 = "127.0.0.1" ascii //weight: 1
        $x_1_3 = "gigabigsvc.dll" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "ServiceMain" ascii //weight: 1
        $x_1_6 = "SetEndOfFile" ascii //weight: 1
        $x_1_7 = "CreatePipe" ascii //weight: 1
        $x_1_8 = "cmd.exe" ascii //weight: 1
        $x_1_9 = "& exit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_AD_2147805592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.AD!MTB"
        threat_id = "2147805592"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 0f b7 01 33 d2 66 2b ?? ?? ?? ?? ?? 33 d2 66 f7 ?? ?? ?? ?? ?? 33 d2 88 06 33 d2 46 33 d2 43 33 d2 83 c1 02 33 d2 3b df 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_AE_2147805837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.AE!MTB"
        threat_id = "2147805837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 0f b7 01 33 d2 66 2b ?? ?? ?? ?? ?? 33 d2 66 f7 ?? ?? ?? ?? ?? 33 d2 88 06 33 d2 46 33 d2 43 33 d2 83 c1 02 33 d7 3b da 7c ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_AF_2147807296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.AF!MTB"
        threat_id = "2147807296"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 0f b7 01 33 d2 66 2b ?? ?? ?? ?? ?? 33 d2 66 f7 ?? ?? ?? ?? ?? 33 d2 88 06 33 d2 46 33 d2 43 33 d2 83 c1 02 33 ?? 3b ?? 7c ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_AG_2147807297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.AG!MTB"
        threat_id = "2147807297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 cd cc cc cc 41 8b c9 41 f7 e1 41 ff c1 c1 ea ?? 8d 04 92 2b c8 48 63 c1 42 0f b6 0c 10 41 32 0c 38 48 8b 44 24 ?? 41 88 0c 00 49 ff c0 4c 3b c3 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_QE_2147807448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.QE!MTB"
        threat_id = "2147807448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "HorekGlepW" ascii //weight: 3
        $x_3_2 = "GetWindowThreadProcessId" ascii //weight: 3
        $x_3_3 = "SetTimer" ascii //weight: 3
        $x_3_4 = "CreateWindowExW" ascii //weight: 3
        $x_3_5 = "PostThreadMessageW" ascii //weight: 3
        $x_3_6 = "PostMessageW" ascii //weight: 3
        $x_3_7 = "CreateFileA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_MP_2147808925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.MP!MTB"
        threat_id = "2147808925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7c 24 18 8b 4c 24 14 83 c7 14 41 89 7c 24 18 3b 4c 24 24 89 4c 24 14 8b 4c 24 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_MP_2147808925_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.MP!MTB"
        threat_id = "2147808925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 6d fc 8a f1 88 4d ff 8a 48 fe 43 32 ca 88 48 0e 8a 48 ff 32 4d fe 88 48 0f 8a 08 32 cd 88 48 10 8a 48 01 32 ce 88 48 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_MP_2147808925_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.MP!MTB"
        threat_id = "2147808925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shellcodeloading/checkSandbox.timeSleep" ascii //weight: 1
        $x_1_2 = "shellcodeloading/checkSandbox.physicalMemory" ascii //weight: 1
        $x_1_3 = "shellcodeloading/checkSandbox.numberOfCPU" ascii //weight: 1
        $x_1_4 = "sync.(*Mutex).Lock" ascii //weight: 1
        $x_1_5 = "crypto/cipher.xorBytes" ascii //weight: 1
        $x_1_6 = "shellcodeloading/aes.AesDecrypt" ascii //weight: 1
        $x_1_7 = "Go buildinf" ascii //weight: 1
        $x_1_8 = "runtime.injectglist" ascii //weight: 1
        $x_1_9 = "sync.(*Mutex).lockSlow" ascii //weight: 1
        $x_1_10 = "sync.(*entry).load" ascii //weight: 1
        $x_1_11 = "shellcodeloading/checkSandbox.CheckSandbox" ascii //weight: 1
        $x_1_12 = "crypto/cipher.NewCBCDecrypter" ascii //weight: 1
        $x_1_13 = "crypto/cipher.xorBytesSSE2" ascii //weight: 1
        $x_1_14 = "crypto/aes.decryptBlockGo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_AB_2147809390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.AB!MTB"
        threat_id = "2147809390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 34 19 39 41 3b ce 72 f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_A_2147810179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.A!MTB"
        threat_id = "2147810179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b d2 0a 0f b6 08 83 e9 30 40 03 d1 80 38 00 75}  //weight: 1, accuracy: High
        $x_1_2 = {33 d2 0f b7 01 33 d2 66 2b 05 [0-4] 66 f7 35 [0-4] 88 06 46 33 d2 43 33 d2 83 c1 02 4f 85 ff 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CobaltStrike_PF_2147812876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.PF!MTB"
        threat_id = "2147812876"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 0f b7 01 33 d2 66 2b 05 ?? ?? ?? ?? 66 f7 35 ?? ?? ?? ?? 88 06 46 8b d2 43 8b d2 83 c1 ?? 4f 8b d7 85 d2 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_PG_2147813166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.PG!MTB"
        threat_id = "2147813166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 8b 45 ?? 31 18 83 45 ?? 04 8b 45 ?? 83 c0 04 89 45 ?? 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_BH_2147813672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.BH!MTB"
        threat_id = "2147813672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 4c 24 ?? e8 ?? ?? ?? ?? 8b 4c 24 ?? 33 08 8b c1 89 44 24 ?? eb 8c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_BN_2147814353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.BN!MTB"
        threat_id = "2147814353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 14 33 8a 04 17 8d 4b ?? 83 e1 07 43 d2 c8 88 02 3b 5d fc 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_BN_2147814353_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.BN!MTB"
        threat_id = "2147814353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d2 03 d1 0f b6 ca 8b 55 ?? 0f b6 89 ?? ?? ?? ?? 32 0c 3a 88 0f 47 83 eb ?? 75 30 00 0f b6 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_AED_2147814382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.AED!MTB"
        threat_id = "2147814382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c1 01 f9 89 f8 31 f0 89 4d e4 23 45 e4 89 c2 31 f2 8b 45 0c 83 c0 04 8b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_RFA_2147815793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.RFA!MTB"
        threat_id = "2147815793"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 c7 45}  //weight: 1, accuracy: High
        $x_1_2 = {8b d8 83 c3 04 e8 ?? ?? ?? ?? 2b d8 01 5d ?? 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 [0-5] c7 [0-5] 00 10 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_RWA_2147815794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.RWA!MTB"
        threat_id = "2147815794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 [0-10] 01 10 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2b d8 01 5d ?? 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 ?? c7 45 ?? 00 10 00 00 8b [0-10] 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_BX_2147816286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.BX!MTB"
        threat_id = "2147816286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 0c 37 0f b6 c2 03 c8 0f b6 c1 8b 4d ?? 8a 04 38 30 04 0b 43 8b 4d ?? 3b 5d ?? 72 c5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_BMM_2147816696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.BMM!MTB"
        threat_id = "2147816696"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {88 06 46 8b d2 43 8b d2 83 c1 02 4f 8b d7 85 fa 75 30 00 66 2b 05 ?? ?? ?? ?? 66 f7 35}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_PAE_2147817375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.PAE!MTB"
        threat_id = "2147817375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 e8 03 e8 03 e8 8b 44 24 ?? 8a 0c 28 8b 44 24 ?? 8a 18 32 d9 8b 4c 24 ?? 88 18 8b 44 24 ?? 40 3b c1 89 44 24 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_BP_2147818231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.BP!MTB"
        threat_id = "2147818231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 39 8e e3 38 f7 e7 8b c7 47 c1 ea 03 8d 0c d2 c1 e1 02 2b c1 8a 80 ?? ?? ?? ?? 30 06 3b fb 72}  //weight: 1, accuracy: Low
        $x_1_2 = "AVBypass.pdb" ascii //weight: 1
        $x_1_3 = "http_dll.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_ME_2147828822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.ME!MTB"
        threat_id = "2147828822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 8b c1 f7 f7 80 c2 35 30 54 0d d4 41 83 f9 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_ST_2147828823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.ST!MTB"
        threat_id = "2147828823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://49.234.65.52/UpdateStream_x86.cab" ascii //weight: 1
        $x_1_2 = "shellcode address" ascii //weight: 1
        $x_1_3 = "HttpWebRequest" ascii //weight: 1
        $x_1_4 = "CallBackHelper" ascii //weight: 1
        $x_1_5 = "WriteLine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_NA_2147830890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.NA!MTB"
        threat_id = "2147830890"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 40 68 00 10 00 00 56 6a 00 89 ?? ?? ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 00 6a 03 6a 00 6a 01 68 00 00 00 80 50 ff 15}  //weight: 2, accuracy: High
        $x_2_3 = {8b 16 89 17 83 c7 04 83 c6 04 83 e9 01 75 f1 8b c8 83 e1 03 74 13 8a 06 88 07 46 47 49 75 f7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_IN_2147832811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.IN!MTB"
        threat_id = "2147832811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c7 8a 49 08 80 e9 05 88 48 08 8b 47 14 83 f8 10}  //weight: 1, accuracy: High
        $x_1_2 = {8b c7 8a 51 07 fe ca 88 50 07 8b 47 14 83 f8 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CobaltStrike_RE_2147833236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.RE!MTB"
        threat_id = "2147833236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 89 4c 46 14 89 46 0c 8b 07 a8 40}  //weight: 1, accuracy: High
        $x_1_2 = {66 89 5c 46 1a 0f b7 5c 47 34 66 85 db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_ES_2147833608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.ES!MTB"
        threat_id = "2147833608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HRp70" ascii //weight: 1
        $x_1_2 = "zkPx3009" ascii //weight: 1
        $x_1_3 = "mgur730yw1.dll" ascii //weight: 1
        $x_1_4 = "drive" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_NVN_2147834253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.NVN!MTB"
        threat_id = "2147834253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {56 6a 04 68 00 30 00 00 57 50 ff 55}  //weight: 2, accuracy: High
        $x_2_2 = {66 0f 3a 0f d9 0c 66 0f 7f 1f 66 0f 6f e0 66 0f 3a 0f c2 0c 66 0f 7f 47 10 66 0f 6f cd 66 0f 3a 0f ec 0c 66 0f 7f 6f 20 8d 7f 30 73 b7}  //weight: 2, accuracy: High
        $x_1_3 = "1.dll" ascii //weight: 1
        $x_1_4 = "av_frame_get_channels" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_NVM_2147834254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.NVM!MTB"
        threat_id = "2147834254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 8b 4d 0c 8a 11 88 10 8b 45 08 83 c0 01 89 45 08 8b 4d 0c 83 c1 01 89 4d 0c eb cd}  //weight: 1, accuracy: High
        $x_1_2 = {6a 40 68 00 10 00 00 68 40 fc 00 00 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {05 00 01 00 00 89 45 e8 8b 4d e4 03 4d ec 8a 55 e8 88 11 eb b3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_GG_2147835643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.GG!MTB"
        threat_id = "2147835643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b8 00 30 00 00 41 b9 40 00 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = "temp\\packed64-temp.pdb" ascii //weight: 1
        $x_1_3 = {09 fb 31 d3 f7 d6 09 de 89 f2 f7 d2 21 ea f7 d5 21 f5 09 d5 89 ca 81 e2 ?? ?? ?? ?? 41 81 e3 ?? ?? ?? ?? 41 09 d3 44 09 c9 41 81 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_EO_2147835691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.EO!MTB"
        threat_id = "2147835691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 02 8b 45 d8 03 45 b0 03 45 e8 89 45 b4 ?? ?? ?? ?? ?? ?? ?? 8b d8 03 5d b4 ?? ?? ?? ?? ?? ?? ?? 2b d8 ?? ?? ?? ?? ?? ?? ?? 2b d8 8b 45 ec 31 18 ?? ?? ?? ?? ?? ?? ?? 8b 55 e8 83 c2 04 03 c2 89 45 e8 ?? ?? ?? ?? ?? ?? ?? 83 c0 04 01 45 ec 8b 45 e8 3b 45 e4 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_AWW_2147836670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.AWW!MTB"
        threat_id = "2147836670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c0 40 0f 28 ca 66 0f ef c8 0f 11 49 a0 0f 28 ca 0f 10 41 b0 66 0f ef c2 0f 11 41 b0 0f 10 41 c0 66 0f ef c2 0f 11 41 c0 0f 10 41 d0 66 0f ef c8 0f 11 49 d0 3b c7 72 c0}  //weight: 1, accuracy: High
        $x_1_2 = "FXVDESDA" ascii //weight: 1
        $x_1_3 = "System.Web.ni.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_RKZ_2147836746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.RKZ!MTB"
        threat_id = "2147836746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 ff 76 20 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {31 46 18 8b 86 c0 00 00 00 35 ?? ?? ?? ?? 29 86 f4 00 00 00 8b 86 d4 00 00 00 83 f0 ?? 0f af 46 1c 89 46 1c 8b 86 94 00 00 00 09 86 d4 00 00 00 81 ff ?? ?? 00 00 0f 8c f0 fe ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {01 46 7c 8b 4e 5c 8b 86 b4 00 00 00 8b d3 c1 ea ?? 88 14 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_UM_2147836804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.UM!MTB"
        threat_id = "2147836804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d3 c1 ea ?? 88 14 01 ff 46 ?? 8b 4e ?? 8b 86 ?? ?? ?? ?? 88 1c 01 ff 46 ?? 8b 86 ?? ?? ?? ?? 83 e8 ?? 31 86 ?? ?? ?? ?? 8b 46}  //weight: 1, accuracy: Low
        $x_1_2 = {31 04 11 b8 ?? ?? ?? ?? 2b 86 ?? ?? ?? ?? 83 c2 ?? 2b 46 ?? 01 46 ?? 8b 86 ?? ?? ?? ?? 01 46 ?? b8 ?? ?? ?? ?? 2b 46 ?? 01 46 ?? 81 fa ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_UZ_2147837257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.UZ!MTB"
        threat_id = "2147837257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 ca 09 88 ?? ?? ?? ?? 8b 88 ?? ?? ?? ?? 2b 88 ?? ?? ?? ?? 31 48 ?? 8b 88 ?? ?? ?? ?? 01 48 ?? 8d 8a ?? ?? ?? ?? 01 88 ?? ?? ?? ?? 8b 88 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 01 48 ?? 8b 48 ?? 2b 88 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 01 48 ?? 81 ff ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_XC_2147837261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.XC!MTB"
        threat_id = "2147837261"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 0c 3a 83 c7 ?? 8b 88 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 03 88 ?? ?? ?? ?? 09 88 ?? ?? ?? ?? 8b 88 ?? ?? ?? ?? 2b 88 ?? ?? ?? ?? 31 48 ?? 8b 88 ?? ?? ?? ?? 01 48 ?? 8b 88 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 01 88 ?? ?? ?? ?? 8b 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_LG_2147837305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.LG!MTB"
        threat_id = "2147837305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b 8e ?? ?? ?? ?? 8b 46 ?? 31 04 11 83 c2 ?? 8b 86 ?? ?? ?? ?? 05 ?? ?? ?? ?? 03 86 ?? ?? ?? ?? 09 86 ?? ?? ?? ?? 8b 86 ?? ?? ?? ?? 2b 86 ?? ?? ?? ?? 31 46 70 8b 86 ?? ?? ?? ?? 01 46 58 8b 86 ?? ?? ?? ?? 2d}  //weight: 1, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_MX_2147837604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.MX!MTB"
        threat_id = "2147837604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb ff 46 ?? 8b 56 ?? 8b 86 ?? ?? ?? ?? c1 e9 ?? 88 0c 02 ff 46 ?? 8b 86 ?? ?? ?? ?? 83 e8 ?? 31 86 ?? ?? ?? ?? 8b 46 ?? 83 e8 ?? 31 46 ?? 8b 4e ?? 8b 86 ?? ?? ?? ?? 88 1c 01 8b 46 ?? ff 46 ?? 2d ?? ?? ?? ?? 01 86 ?? ?? ?? ?? 8b 86 ?? ?? ?? ?? 29 46 ?? 8b 4e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_GCD_2147838178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.GCD!MTB"
        threat_id = "2147838178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 d9 89 c7 89 85 ?? ?? ?? ?? 31 c0 f3 a4 39 c3 74 ?? 8b 95 ?? ?? ?? ?? 80 34 02 03 40 eb}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualAllocEx" ascii //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_FR_2147838233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.FR!MTB"
        threat_id = "2147838233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 19 2c 0a 34 cc 88 04 19 41 3b 4f 28 72 f0 56 ff 57 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_ZQ_2147838396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.ZQ!MTB"
        threat_id = "2147838396"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 04 32 83 c6 ?? 8b 41 ?? 83 f0 ?? 29 81 ?? ?? ?? ?? 8b 81 ?? ?? ?? ?? 83 f0 ?? 0f af 41 ?? 89 41 ?? 8b 81 ?? ?? ?? ?? 01 41 ?? 81 fe ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_RDA_2147838560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.RDA!MTB"
        threat_id = "2147838560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4d 10 89 c2 83 e2 07 8a 14 11 8b 4d 08 32 14 01 88 14 06 40 39 c3}  //weight: 2, accuracy: High
        $x_1_2 = "%c%c%c%c%c%c%c%c%cnetsvc\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_RA_2147838952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.RA!MTB"
        threat_id = "2147838952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 0c 40 00 00 00 c7 44 24 08 00 30 00 00 89 44 24 04 c7 04 24 00 00 00 00 ff 15 [0-48] 89 c1 83 e1 07 d2 ca 88 54 03 ff 89 c2 83 c0 01 39 d6 75 e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_SC_2147839736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.SC!MTB"
        threat_id = "2147839736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 0c 02 ff 46 ?? 8b 86 ?? ?? ?? ?? 83 e8 ?? 31 86 ?? ?? ?? ?? 8b 46 ?? 83 e8 ?? 31 46 ?? 8b 46 ?? 8b 8e ?? ?? ?? ?? 88 1c 01 8b 46 ?? ff 46 ?? 2d ?? ?? ?? ?? 01 86 ?? ?? ?? ?? 8b 86}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_XZQ_2147839743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.XZQ!MTB"
        threat_id = "2147839743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 01 46 ?? 8b 46 ?? 8b 8e ?? ?? ?? ?? 8b d3 c1 ea ?? 88 14 01 ff 46 ?? 8b 46 ?? 29 86 ?? ?? ?? ?? b8 ?? ?? ?? ?? 2b 86 36 00 83 c7 ?? 0f af 5e ?? 8b 86}  //weight: 1, accuracy: Low
        $x_1_2 = {88 1c 0a ff 40 ?? 8b 48 ?? 49 01 88 ?? ?? ?? ?? b9 ?? ?? ?? ?? 2b 88 ?? ?? ?? ?? 2b 48 ?? 01 48 ?? 8b 88 ?? ?? ?? ?? 33 88 ?? ?? ?? ?? 31 48 ?? 8b 88 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 31 48 ?? 81 fe ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_SE_2147839907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.SE!MTB"
        threat_id = "2147839907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d3 c1 ea ?? 88 14 01 b8 ?? ?? ?? ?? 2b 46 ?? 01 46 ?? 8b 86 ?? ?? ?? ?? 33 86 ?? ?? ?? ?? 33 46 ?? ff 46 ?? 35 ?? ?? ?? ?? 8b 4e ?? 89 46}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_EB_2147840232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.EB!MTB"
        threat_id = "2147840232"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 1c 3e 02 1c 16 0f b6 fb 0f b6 1c 3e 8b 7d ?? 8b 75 ?? 32 1c 07 88 1c 06 40 39 45 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_EB_2147840232_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.EB!MTB"
        threat_id = "2147840232"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 55 08 89 55 08 8b 45 0c 2b 45 ec 8b 4d 10 1b 4d f0 89 45 0c 89 4d 10}  //weight: 2, accuracy: High
        $x_1_2 = "\\pipe\\CYM_outputpipe_63be34402e2d8f687eda52e7" wide //weight: 1
        $x_1_3 = "explorer.exe,Taskmgr.exe,procexp.exe,procexp64.exe,perfmon.exe" wide //weight: 1
        $x_1_4 = "hide_file,hide_process" wide //weight: 1
        $x_1_5 = ".CymCrypt" wide //weight: 1
        $x_1_6 = "backup file %s, this file will not be encrypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_SG_2147840251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.SG!MTB"
        threat_id = "2147840251"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b ca 01 48 ?? 81 c2 ?? ?? ?? ?? 8b 88 ?? ?? ?? ?? 8b a8 ?? ?? ?? ?? 33 cd 33 48 ?? 81 f1 ?? ?? ?? ?? 8b b8 ?? ?? ?? ?? 89 48 ?? 8b 48 ?? 81 c1 ?? ?? ?? ?? ff 40 ?? 0f af 88 ?? ?? ?? ?? 89 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_DBA_2147840298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.DBA!MTB"
        threat_id = "2147840298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {35 9d 33 00 00 50 8d 81 ee fc ff ff 50 8b 44 24 48 56 05 0d 0e 00 00 50 ff 74 24 64 8d 81 a0 01 00 00 50 8d 87 7b ec ff ff 81 f7 7f 2e 00 00 50 8d 81 aa 08 00 00 50 57 e8 ef 19 01 00 8b 44 24 58 83 c4 30 35 36 32}  //weight: 4, accuracy: High
        $x_1_2 = "YnJRE282B9" ascii //weight: 1
        $x_1_3 = "KvrQI36C9F" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_DBB_2147840320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.DBB!MTB"
        threat_id = "2147840320"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {35 53 2a 00 00 81 c6 19 d3 ff ff 3b c8 0f 8d ce 01 00 00 8d 81 f9 04 00 00 3b f0 0f 8f c0 01 00 00 8b c3 35 e7 2c 00 00 57 3b d0 0f 84 fb 00 00 00 8b 7c 24 38 8d 42 ed 57 50 8b 44 24 24 35 43 03 00 00 50 8d 81 e5 fe ff ff 50}  //weight: 4, accuracy: High
        $x_1_2 = "YncgA40d33" ascii //weight: 1
        $x_1_3 = "GIbOTN65" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_DBC_2147840395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.DBC!MTB"
        threat_id = "2147840395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {81 f1 af 05 00 00 05 12 2d 75 47 01 86 84 00 00 00 8d 87 ba 3d 00 00 56 52 50 8b 44 24 3c 05 79 0a 00 00 51 50 8d 82 85 0b 00 00 35 8b 14 00 00 50 e8 ca a7 ff ff 83 c4 18 81 f5 97 0c 00 00}  //weight: 4, accuracy: High
        $x_1_2 = "Whtwot028m72" ascii //weight: 1
        $x_1_3 = "SnsB307h" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_CPP_2147840465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.CPP!MTB"
        threat_id = "2147840465"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 04 0a 88 04 1a 42 84 c0 75}  //weight: 5, accuracy: High
        $x_5_2 = {33 db f7 d6 f7 de 81 c3 ?? ?? ?? ?? 2b f5 c1 e3 ?? f7 de f7 d0 33 d0 e2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_SI_2147840725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.SI!MTB"
        threat_id = "2147840725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 0c 32 b9 ?? ?? ?? ?? 8b 90 01 04 83 c6 ?? 8b 78 ?? 2b ca 01 48 ?? 8b 88 ?? ?? ?? ?? 33 cf 81 c1 ?? ?? ?? ?? 33 ca 89 88}  //weight: 1, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_SL_2147840929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.SL!MTB"
        threat_id = "2147840929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 0c 3a 83 c7 ?? 8b 88 ?? ?? ?? ?? 2b 48 ?? 81 e9 ?? ?? ?? ?? 01 88 ?? ?? ?? ?? 8b 88 ?? ?? ?? ?? 01 88 ?? ?? ?? ?? 81 ff ?? ?? ?? ?? 7c 40 00 8b 48 ?? 29 48 ?? 8b 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_CPQ_2147841032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.CPQ!MTB"
        threat_id = "2147841032"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 04 0a 88 04 1a 42 84 c0 75}  //weight: 5, accuracy: High
        $x_5_2 = {c1 cf 1b 47 33 d9 c1 eb ?? 03 1d ?? ?? ?? ?? 21 ?? ?? ?? ?? ?? 3b fb 78 ?? c1 ?? ?? 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? e2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_RDB_2147841306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.RDB!MTB"
        threat_id = "2147841306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1mikuny0uarexlaohei2i" ascii //weight: 1
        $x_2_2 = {46 81 e6 ff 00 00 80 79 08 4e 81 ce 00 ff ff ff 46 8a 8c 35 f0 fe ff ff 0f b6 d1 03 fa 81 e7 ff 00 00 80 79 08 4f 81 cf 00 ff ff ff 47 0f b6 84 3d f0 fe ff ff 88 84 35 f0 fe ff ff 88 8c 3d f0 fe ff ff 0f b6 84 35 f0 fe ff ff 03 c2 0f b6 c0 0f b6 84 05 f0 fe ff ff 30 84 1d e0 d6 ff ff 43}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_VII_2147842149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.VII!MTB"
        threat_id = "2147842149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 04 11 83 c2 ?? 8b 86 ?? ?? ?? ?? 2b 46 ?? 2d ?? ?? ?? ?? 01 86 ?? ?? ?? ?? 8b 86 ?? ?? ?? ?? 01 86 ?? ?? ?? ?? 81 fa ?? ?? ?? ?? 7c ?? 46 00 2b 46 ?? 01 46 ?? 8b 46 ?? 29 46 ?? 8b 8e ?? ?? ?? ?? 8b 86}  //weight: 1, accuracy: Low
        $x_1_2 = "xiaopin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_SZ_2147843089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.SZ!MTB"
        threat_id = "2147843089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 71 ff 12 80 31 12 80 71 01 12 80 71 02 12 80 71 03 12 80 71 04 12 80 71 05 12 80 71 06 12 80 71 07 12 80 71 08 12 80 71 09 12 80 71 0a 12 80 71 0b 12 80 71 0c 12 80 71 0d 12 80 71 0e 12}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_EC_2147843308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.EC!MTB"
        threat_id = "2147843308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {6a c6 84 24 ?? ?? ?? ?? c1 c6 84 24 ?? ?? ?? ?? 57 c6 84 24 ?? ?? ?? ?? 52 c6 84 24 ?? ?? ?? ?? f7 c7 44 24 ?? 50 10 03 00 8b 44 24 ?? 41 b9 04 00 00 00 41 b8 00 30 00 00 8b d0 33 c9}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_LKQ_2147843874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.LKQ!MTB"
        threat_id = "2147843874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3b 55 0c 7d 0e 89 d1 83 e1 07 8a 0c 08 30 0c 13 42 eb ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_ZL_2147844369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.ZL!MTB"
        threat_id = "2147844369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 71 8a 4c 71 01 88 44 24 10 88 4c 24 14 8b 44 24 10 8b 4c 24 14 25 ff 00 00 00 81 e1 ff 00 00 00 68 48 60 40 00 8d 14 40 8d 04 90 8d bc 41 25 f9 ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {8a 14 16 33 c9 8a cf 32 ca 51 56 8d 4c 24 10 e8 02 17 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_EM_2147844978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.EM!MTB"
        threat_id = "2147844978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {44 30 c0 34 01 44 89 c3 44 08 cb 80 f3 01 08 c3 44 89 ca 44 30 c2 41 20 d1 44 20 c2 45 89 c8 41 20 d0 44 30 ca 44 08 c2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_LKU_2147845333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.LKU!MTB"
        threat_id = "2147845333"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 40 3c 31 04 11 83 c2 04 8b 45 ?? 01 45 ?? 8b 0d ?? ?? ?? ?? 8b 45 ?? ?? ?? ?? ?? ?? 01 81 ac 00 00 00 81 fa ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {01 41 40 8b 0d ?? ?? ?? ?? 8b 81 d0 00 00 00 35 ?? ?? ?? ?? 09 41 40 b8 ?? ?? ?? ?? 2b 86 80 00 00 00 01 05 ?? ?? ?? ?? 81 ff ?? ?? 00 00 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CobaltStrike_WMB_2147845423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.WMB!MTB"
        threat_id = "2147845423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 14 08 83 c0 04 8b 0d ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 81 f1 ?? ?? ?? ?? 09 0d ?? ?? ?? ?? 8b ce 2b 0d ?? ?? ?? ?? 01 0d ?? ?? ?? ?? b9 ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 01 0d ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 3d ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
        $x_1_2 = "StartXpr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_LKW_2147846183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.LKW!MTB"
        threat_id = "2147846183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 d7 8b 45 ?? 83 e7 ?? 8a 04 38 30 04 0a 42 83 fa ?? 75 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_DG_2147847074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.DG!MTB"
        threat_id = "2147847074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vscodeWorkSpace\\shellcode\\whiteandblack" ascii //weight: 1
        $x_1_2 = "AvastSvc.exe" ascii //weight: 1
        $x_1_3 = "kpm_tray.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_CC_2147847095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.CC!MTB"
        threat_id = "2147847095"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 ce 0b d1 8b 0d d0 75 46 00 83 c1 fe 89 15 c4 75 46 00 03 ca 0b f1 8b 0d a4 75 46 00 89 35 60 75 46 00 31 3c 08 83 c0 04 8b 15 90 75 46 00 2b 15 64 75 46 00 33 15 64 75 46 00 8b 3d 84 75 46 00 81 f2 88 0f 0d 00 03 3d c0 75 46 00 89 15 64 75 46 00 89 3d 84 75 46 00 3d 44 03 00 00 0f 8c 47 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_UNK_2147847817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.UNK!MTB"
        threat_id = "2147847817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 88 cc 00 00 00 8b 90 2c 01 00 00 8b 88 80 00 00 00 31 0c 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_GJK_2147847992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.GJK!MTB"
        threat_id = "2147847992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 ca c1 ea ?? 89 d0 f7 e3 89 c8 6b d2 1c 29 d0 0f b6 84 05 ?? ?? ?? ?? 30 04 0e 83 c1 01 81 f9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_GJK_2147847992_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.GJK!MTB"
        threat_id = "2147847992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {23 cf c1 c8 16 33 d0 89 5d d8 8b 45 e4 03 d6 23 45 e0 8b 75 ac 0b c1 8b 4d fc 03 c2 33 4d f0 8b d3 89 45 c8 23 cb}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_GJJ_2147848013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.GJJ!MTB"
        threat_id = "2147848013"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 c2 8b 45 e0 01 d0 0f b6 00 31 d8 88 01 83 45 e4 01 8b 55 e4 8b 45 d0 39 c2 0f 82}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_CRIZ_2147848822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.CRIZ!MTB"
        threat_id = "2147848822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d 08 89 c1 8d 50 01 83 e1 ?? 8a 0c 0f 8b 7d 14 32 0c 07 88 0c 03 89 d0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_GKE_2147849513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.GKE!MTB"
        threat_id = "2147849513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 8b 5d 14 4b 8b 4d 10 33 d2 3b f3 0f 45 d6 8b 75 08 8a 0c 0a 30 0c 30 40 8d 72 01 3b c7 72}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_LKAD_2147849544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.LKAD!MTB"
        threat_id = "2147849544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 56 33 ff 57 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {b1 66 30 88 ?? ?? ?? ?? 40 3b c6 7c f5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_PBF_2147849882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.PBF!MTB"
        threat_id = "2147849882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {da 8b db c1 ee 1d 89 1d ?? ?? ?? ?? 42 81 2d ?? ?? ?? ?? 28 e7 af 8d c1 c2 0e 0b c3 81 eb 81 09 dd 44 bb a2 d4 a3 32 4b f7 c1 ?? ?? ?? ?? 72 ?? bb ?? ?? ?? ?? 03 f8 2b d1 ff c9 75 b7}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 c6 05 4b 0b c5 47 81 f0 ?? ?? ?? ?? f7 da 81 f7 ?? ?? ?? ?? 21 15 ?? ?? ?? ?? c1 ea 1f c1 e6 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_PBG_2147849883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.PBG!MTB"
        threat_id = "2147849883"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c2 01 89 55 f0 8b 45 f0 3b 45 0c 73 ?? 8b 45 f0 33 d2 b9 04 00 00 00 f7 f1 0f b6 54 15 fc 8b 45 08 03 45 f0 0f be 08 33 ca 8b 55 08 03 55 f0 88 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_CD_2147850055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.CD!MTB"
        threat_id = "2147850055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 02 33 c1 8b 4d ?? 03 4d ?? 88 01 8b 55 ?? 03 55 ?? 0f be 0a 03 4d ?? 8b 45 ?? 33 d2 be ?? ?? ?? ?? f7 f6 03 ca 8b c1 33 d2 b9 ?? ?? ?? ?? f7 f1 89 55 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_ZF_2147850135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.ZF!MTB"
        threat_id = "2147850135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 04 31 83 c6 ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 c1 a3 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 8b 42 ?? 03 c1 8b 0d ?? ?? ?? ?? 33 0d ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 05 ?? ?? ?? ?? 03 c1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_CRDA_2147850281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.CRDA!MTB"
        threat_id = "2147850281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f ef c1 0f 11 84 05 ?? ?? ?? ?? 0f 10 84 05 ?? ?? ?? ?? 66 0f ef c1 0f 11 84 05 ?? ?? ?? ?? 0f 10 84 05 ?? ?? ?? ?? 66 0f ef c1 0f 11 84 05 ?? ?? ?? ?? 0f 10 84 05 ?? ?? ?? ?? 66 0f ef c1 0f 11 84 05 ?? ?? ?? ?? 83 c0 40 3d c0 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_ZH_2147850507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.ZH!MTB"
        threat_id = "2147850507"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3139342e3138302e34382e31353200" ascii //weight: 1
        $x_1_2 = "4d6f7a696c6c612f352e30202857696e646f7773204e5420362e333b2054726964656e742f372e303b2072763a31312e3029206c696b65204765636b6f" ascii //weight: 1
        $x_1_3 = "4163636570742d456e636f64696e673a20677a69702c206465666c6174650d0a557365722d4167656e743a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_MQA_2147851133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.MQA!MTB"
        threat_id = "2147851133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 e9 89 ca c1 e2 04 03 54 24 1c 8d 2c 0e 31 d5 89 ca c1 ea 05 03 54 24 18 31 ea 29 d3 81 c6 ?? ?? ?? ?? 83 c0 ff 75 c1 8b 04 24 8b 54 24 10 89 1c d0 89 c3 89 4c d0 04 8b 7c 24 04 8b 44 24 0c 31 07 83 c2 01 8b 74 24 08 39 f2 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_RDD_2147851691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.RDD!MTB"
        threat_id = "2147851691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 10 0f be 14 10 33 ca a1 ?? ?? ?? ?? 8b 50 10 8b 45 fc 88 0c 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_RDE_2147851867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.RDE!MTB"
        threat_id = "2147851867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 45 fc c6 45 f0 46 c6 45 f1 69 c6 45 f2 6e c6 45 f3 64 c6 45 f4 57 c6 45 f5 69 c6 45 f6 6e c6 45 f7 64 c6 45 f8 6f c6 45 f9 77 c6 45 fa 57}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_DY_2147852680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.DY!MTB"
        threat_id = "2147852680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 33 d2 f7 75 f8 8a 44 15 ?? 30 44 0b 04 41 3b ce 72 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_DY_2147852680_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.DY!MTB"
        threat_id = "2147852680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 f4 01 f6 d4 51 81 c1 f1 00 00 00 51 59 b9 c5 00 00 00 41 81 c1 0e 01 00 00 49 b9 7e 00 00 00 87 c9 41 41 87 c9 59 d0 cc 8a 04 33 32 c4 32 07 88 07 47 4b 79 02 89 d3 51 56 53 57 52 87 d6 83 ce 51 4f 81 f2 9b 00 00 00 81 c1 07 01 00 00 81 f3 5e 01 00 00 87 f6 83 f7 23 5a 5f 5b 5e 59 49 75}  //weight: 1, accuracy: High
        $x_1_2 = "HUB DOGS YOURSELF HOLLOW REPRESENT LANDS KNOCK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_RDF_2147852866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.RDF!MTB"
        threat_id = "2147852866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 08 0f be 0c 10 8b 55 0c 03 55 f8 0f b6 02 33 c1 8b 4d 0c 03 4d f8 88 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_LKAK_2147852871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.LKAK!MTB"
        threat_id = "2147852871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {76 1d 0f b6 fa 83 ef 11 8d 4e 01 83 ff 04 0f 82 aa 00 00 00 8a 11 88 10 40 41 4f 75 f7}  //weight: 1, accuracy: High
        $x_1_2 = {8a 17 88 10 8a 57 01 88 50 01 8a 57 02 41 88 50 02 83 c0 03 8b de 0f b6 79 ff 83 e7 03}  //weight: 1, accuracy: High
        $x_1_3 = {6a 40 68 00 10 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_GIR_2147852912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.GIR!MTB"
        threat_id = "2147852912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 81 e2 ff 00 00 00 8a 8c 15 fc fe ff ff 0f b6 c1 03 f8 81 e7 ?? ?? ?? ?? 0f b6 84 3d fc fe ff ff 88 84 15 fc fe ff ff 88 8c 3d fc fe ff ff 0f b6 c9 81 e1 ff 00 00 80 79 ?? 49 81 c9 00 ff ff ff 41 0f b6 84 15 ?? ?? ?? ?? 03 c8 81 e1 ff 00 00 80 79 ?? 49 81 c9 00 ff ff ff 41 0f b6 84 0d fc fe ff ff 30 04 33 46 81 fe 50 38 03 00 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_YAN_2147853506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.YAN!MTB"
        threat_id = "2147853506"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d1 03 fa 81 e7 ff 00 00 80 79 ?? 4f 81 cf 00 ff ff ff 47 0f b6 84 3d 7c fe ff ff 88 84 35 7c fe ff ff 88 8c 3d 7c fe ff ff 0f b6 84 35 7c fe ff ff 8b 8d 78 fd ff ff 03 c2 8b 95 74 fd ff ff 0f b6 c0 0f b6 84 05 7c fe ff ff 30 04 0a 42 89 95 74 fd ff ff 3b d3 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_PBH_2147888237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.PBH!MTB"
        threat_id = "2147888237"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 89 c0 f7 e9 c1 fa 02 44 89 c0 c1 f8 1f 29 c2 8d 04 d2 01 c0 44 89 c7 29 c7 89 f8 48 98 48 8b 15 ?? ?? ?? ?? 0f b6 14 02 42 32 94 04 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 42 88 14 00 49 83 c0 01 4d 39 c8 75 bb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_CO_2147888717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.CO!MTB"
        threat_id = "2147888717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 83 c1 ?? 89 4d ?? 8b 55 ?? 3b 55 ?? 73 ?? 0f b6 45 ?? 8b 4d ?? 03 4d ?? 0f be 11 33 d0 8b 45 ?? 03 45 ?? 88 10 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_AJ_2147888728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.AJ!MTB"
        threat_id = "2147888728"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 14 08 8b d3 ff 46 40 8b 86 d4 00 00 00 48 c1 ea 08 01 86 e4 00 00 00 a1 ?? ?? ?? ?? 8b 48 40 8b 46 74 88 14 01 a1 ?? ?? ?? ?? ff 40 40 8b [0-5] 0f [0-6] 89 86 b8 00 00 00 a1 ?? ?? ?? ?? 8b 4e 74 88 1c 08 a1 ?? ?? ?? ?? ff 05 ?? ?? ?? ?? 8b 00 01 86 b8 00 00 00 81 ff ?? ?? ?? ?? 0f 8c ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_B_2147888912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.B!MTB"
        threat_id = "2147888912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c0 ac c1 c7 ?? 03 f8 3c ?? 75 ?? 39 7c 24 08 75}  //weight: 2, accuracy: Low
        $x_2_2 = {49 8b 34 8a 03 f3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_CCBG_2147891434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.CCBG!MTB"
        threat_id = "2147891434"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 24 97 a9 3e 68 19 db 6f 3e 68 19 db 6f 3e 68 19 db 6f 3e 68 61 70 a5 3e e8 ?? ?? ?? ?? 83 c4 14 33 c0 3b ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_FST_2147891822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.FST!MTB"
        threat_id = "2147891822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b c1 8b 8e 88 00 00 00 01 46 40 8b 46 38 88 1c 01 ff 46 38 a1 ?? ?? ?? ?? 8b 48 08 a1 ?? ?? ?? ?? 48 03 c1 09 86 9c 00 00 00 8b 46 08 48 31 05 ?? ?? ?? ?? 8b 4e 60 8b 46 20 83 c1 fe 03 c1 31 86 94 00 00 00 b8 47 d2 13 00 8b 0d ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 01 41 54 b9 01 00 00 00 a1 ?? ?? ?? ?? 2b 48 08 2b 4e 78 01 4e 08 81 ff 20 1f 00 00 0f 8c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_MC_2147892057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.MC!MTB"
        threat_id = "2147892057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 40 20 33 86 ?? ?? ?? ?? 35 eb fa f5 ff 09 46 70 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 05 8b 4a 38 2b 4e 7c 03 c1 a3 ?? ?? ?? ?? 8b 82 3c 01 00 00 40 0f af 46 4c 89 46 4c 3b 3d ?? ?? ?? ?? 77}  //weight: 2, accuracy: Low
        $x_2_2 = "XtU292" ascii //weight: 2
        $x_2_3 = "Tnlt887by3" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_LKBB_2147893358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.LKBB!MTB"
        threat_id = "2147893358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f1 2a 83 f1 5d 83 f1 3c 8b 95 ?? ?? ff ff 88 8a ?? ?? ?? ?? 8b 85 40 fe ff ff 83 c0 01 89 85 ?? ?? ff ff eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_MG_2147893884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.MG!MTB"
        threat_id = "2147893884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 ea 18 01 86 c0 00 00 00 8b 46 50 8b 8e a0 00 00 00 88 14 01 8b cb ff 46 50 a1 ?? ?? ?? ?? 8b 56 50 c1 e9 10 8b 80 a0 00 00 00 88 0c 02 8b d3 ff 46 50 a1 ?? ?? ?? ?? c1 ea 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_LKBC_2147893898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.LKBC!MTB"
        threat_id = "2147893898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 68 ?? ?? 03 00 8b 85 ?? ?? ?? ?? 05 ?? ?? 03 00 50 68 ?? ?? 04 00 68 00 ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_C_2147894361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.C!MTB"
        threat_id = "2147894361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "krpt_RegisterWERHandler" ascii //weight: 2
        $x_2_2 = "krpt_RemoveDllFilterProtectDetour" ascii //weight: 2
        $x_2_3 = "krpt_RemoveRuntimeProtectDetour" ascii //weight: 2
        $x_2_4 = "krpt_RuntimeProtect" ascii //weight: 2
        $x_2_5 = "_force_link_krpt" ascii //weight: 2
        $x_2_6 = "rundll32" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_CCDE_2147894579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.CCDE!MTB"
        threat_id = "2147894579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 83 c5 03 55 53 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {88 0e 0f b6 50 ?? 0f b6 54 94 ?? 0f b6 48 ?? c0 e2 ?? 0a 54 8c ?? 83 c6 ?? 88 56 fe 83 c0 ?? 83 ef ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_RAR_2147895177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.RAR!MTB"
        threat_id = "2147895177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d8 83 f3 01 0f af d8 c1 eb 08 32 1c 0f 8b 4d f0 8a d3 e8 69 ee ff ff 8b 4d e4 8b 45 f0 88 1c 0f 47 3b fe 72 cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_KJ_2147895236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.KJ!MTB"
        threat_id = "2147895236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c8 83 f0 ?? 25 ?? ?? ?? ?? 21 f9 09 f2 89 55 ?? 09 c8 89 45 ?? 8b 4d ?? 8b 45 ?? 31 c8 88 45 ?? 8b 45 ?? 8a 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_CCDQ_2147895749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.CCDQ!MTB"
        threat_id = "2147895749"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c8 fc 40 8a 80 ?? ?? ?? ?? 30 87 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 80 b7 ?? ?? ?? ?? ?? 85 c0 b8 01 00 00 00 0f 45 f0 47 3b 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_ZN_2147895912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.ZN!MTB"
        threat_id = "2147895912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f af da 8b d3 c1 ea ?? 88 14 01 8b d3 ff 47 ?? 8b 87 ?? ?? ?? ?? 2d ?? ?? ?? ?? c1 ea 08 31 05 ?? ?? ?? ?? 8b 4f ?? 8b 87 ?? ?? ?? ?? 88 14 01 ff 47 ?? 8b 4f ?? a1 ?? ?? ?? ?? 88 1c 01 ff 47 ?? 81 fe ?? ?? ?? ?? 0f 8c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_HK_2147896295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.HK!MTB"
        threat_id = "2147896295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 24 83 ec ?? 89 3c 24 89 0c 24 89 e1 81 c1 ?? ?? ?? ?? 83 c1 ?? 33 0c 24 31 0c 24 33 0c 24 5c e9}  //weight: 1, accuracy: Low
        $x_1_2 = {43 00 4b 00 94 00 4e ?? ce 32 b9 ?? ?? ?? ?? ?? d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_HL_2147896296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.HL!MTB"
        threat_id = "2147896296"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a5 53 32 1c 7b a1 ?? ?? ?? ?? 18 a3 ?? ?? ?? ?? ?? 69 ?? ae 35}  //weight: 1, accuracy: Low
        $x_1_2 = {a4 00 a4 00 ?? ?? ?? ?? 41 00 2b 00 0c ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_PHQ_2147896297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.PHQ!MTB"
        threat_id = "2147896297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 0f b6 1c 00 4d 8b 22 4d 0f af dc 4c 01 da 41 88 14 00 48 ff c0 48 c1 fa 08}  //weight: 1, accuracy: High
        $x_1_2 = {44 0f b6 0c 0e ff c2 44 0f b6 d2 46 8b 1c 90 44 01 df 44 0f b6 e7 46 8b 2c a0 46 89 2c 90 46 89 1c a0 47 8d 14 2b 45 0f b6 d2 46 33 0c 90 44 88 0c 0b 48 ff c1}  //weight: 1, accuracy: High
        $x_1_3 = "o)el0A&Rz)jA*3*>NdORWW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_DL_2147896684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.DL!MTB"
        threat_id = "2147896684"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff d1 50 8b 85 50 f8 ff ff c7 04 24 00 00 00 00 ff d0 50 a1 78 71 b8 6b 89 85 44 f8 ff ff c7 04 24 00 00 00 00 ff d0}  //weight: 1, accuracy: High
        $x_1_2 = "quiomnissitaliquidmolestias24.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_YAL_2147897176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.YAL!MTB"
        threat_id = "2147897176"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ec 56 0f b6 45 08 0f b6 c0 0f b6 55 0c 0f b6 d2 33 c2 88 45 fc}  //weight: 1, accuracy: High
        $x_1_2 = {88 45 d0 83 c4 08 b8 ?? ?? ?? ?? 03 45 ec 0f b6 00 0f b6 c0 83 f0 49 ba ?? ?? ?? ?? 03 55 ec 88 02 b8 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_HO_2147897657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.HO!MTB"
        threat_id = "2147897657"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 89 45 ?? 81 7d ?? ?? ?? ?? ?? 73 ?? 8b 45 ?? 03 45 ?? 0f b6 08 8b 55 ?? 03 55 ?? 0f b6 02 33 c1 8b 4d ?? 03 4d ?? 88 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_HT_2147898345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.HT!MTB"
        threat_id = "2147898345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 8d 0c 3a 83 e0 ?? 8a 80 ?? ?? ?? ?? 32 04 0e 42 88 01 3b 15 ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_ML_2147898558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.ML!MTB"
        threat_id = "2147898558"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 38 31 d2 89 c8 01 cf 41 89 7d f0 bf 0d 00 00 00 f7 f7 8a 44 16 0c 8b 55 f0 30 02 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_YAQ_2147898635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.YAQ!MTB"
        threat_id = "2147898635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3b 4d 10 73 13 89 c8 31 d2 8b 3b f7 f6 01 cf 41 8a 44 13 0c 30 07 eb e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_LKBD_2147899612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.LKBD!MTB"
        threat_id = "2147899612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 88 00 ?? ?? ?? 83 f1 ?? 83 f1 ?? 83 f1 ?? 83 f1 ?? 8b 95 ?? ?? ff ff 88 8a ?? ?? ?? ?? 8b 85 ?? ?? ff ff 83 c0 01 89 85 ?? ?? ff ff eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_SPR_2147899736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.SPR!MTB"
        threat_id = "2147899736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 45 fc 33 c2 33 c1 81 3d ?? ?? ?? ?? a3 01 00 00 89 45 fc 75 20}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_NAX_2147899878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.NAX!MTB"
        threat_id = "2147899878"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 8a 84 1d f0 fe ff ff 88 84 3d f0 fe ff ff 88 8c 1d f0 fe ff ff 0f b6 84 3d f0 fe ff ff 8b 8d 3c fd ff ff 03 c2 8b 95 64 fd ff ff 0f b6 c0 8a 84 05 f0 fe ff ff 30 04 11 41 89 8d ?? ?? ?? ?? 3b ce 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_ZR_2147900167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.ZR!MTB"
        threat_id = "2147900167"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://archivo-pdf174.com/wm2203928265186" wide //weight: 1
        $x_1_2 = "zSrVRmBffNveFisZYUaSxTmugvOrqK" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_CCGM_2147900514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.CCGM!MTB"
        threat_id = "2147900514"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 d2 8b 4d 08 f7 35 ?? ?? ?? ?? 6b d2 0c 39 8a ?? ?? ?? ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_TB_2147900812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.TB!MTB"
        threat_id = "2147900812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 63 c0 46 8a 04 02 41 b9 ?? ?? ?? ?? 31 d2 41 f7 f1 8b 44 24 ?? 41 89 d1 48 8b 54 24 ?? 4d 63 c9 46 32 04 0a 48 63 d0 44 88 04 11 83 c0 01 31 c9 89 ca 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? 48 29 ca 31 c9 49 b8 ?? ?? ?? ?? ?? ?? ?? ?? 4c 29 c1 83 f8 ?? 48 0f 44 ca}  //weight: 1, accuracy: Low
        $x_1_2 = "/model/install.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_TB_2147900812_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.TB!MTB"
        threat_id = "2147900812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\Users\\Public" ascii //weight: 10
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_10_3 = "NewWYDll\\NewWYDll\\Release\\NewWYDll.pdb" ascii //weight: 10
        $x_10_4 = "%s\\updater.exe" ascii //weight: 10
        $x_1_5 = "%s\\libcurl.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_TA_2147901084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.TA!MTB"
        threat_id = "2147901084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 58 48 8b bc 24 d0 00 00 00 48 8b 74 24 30 83 e0 07 44 8a 14 07 48 8b 84 24 c0 00 00 00 44 32 14 30 48 8b 05 3b 5b 02 00 81 38 ?? ?? ?? ?? 0f 8e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_TD_2147902001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.TD!MTB"
        threat_id = "2147902001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {88 0c 38 8b cf 8b 7c 24 18 0f b6 04 0e 03 c2 0f b6 c0 8a 04 08 32 04 1f 88 03 43 8b 44 24 20 83 ed 01 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_TE_2147902474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.TE!MTB"
        threat_id = "2147902474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f af da 8b d3 c1 ea 10 88 14 01 8b d3 ff 47 ?? 8b 87 ?? ?? ?? ?? 2d ?? ?? ?? ?? c1 ea 08 31 05 54 7a 4d 00 8b 47 6c 8b 8f ?? ?? ?? ?? 88 14 01 ff 47 ?? 8b 4f ?? a1 ?? ?? ?? ?? 88 1c 01 ff 47 6c 81 fe ?? ?? ?? ?? 0f 8c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_HC_2147902621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.HC!MTB"
        threat_id = "2147902621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 e4 83 c0 01 89 45 e4 8b 4d e4 3b 4d b0 73 27 8b 55 e4 0f b6 8a ?? ?? ?? ?? 8b 45 e4 33 d2 be ?? ?? ?? ?? f7 f6 0f b6 54 15 ?? 33 ca 8b 45 f0 03 45 e4 88 08 eb}  //weight: 10, accuracy: Low
        $x_1_2 = "[antimalware_provider] :: WerHandlerImpl::UnregisterWer()" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_ACB_2147903159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.ACB!MTB"
        threat_id = "2147903159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 dc 43 72 79 70 c7 45 e0 74 44 65 63 c7 45 e4 72 79 70 74 c6 45 e8 00 ff d7}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 ac 43 72 79 70 c7 45 b0 74 44 65 72 c7 45 b4 69 76 65 4b 66 c7 45 b8 65 79 c6 45 ba 00 ff d7}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 94 76 00 61 00 c7 45 98 70 00 69 00 c7 45 9c 33 00 32 00 c7 45 a0 2e 00 64 00 c7 45 a4 6c 00 6c 00 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_ACS_2147903160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.ACS!MTB"
        threat_id = "2147903160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 ec 65 00 00 00 c7 45 cc 0c 00 00 00 c7 45 d0 0c 00 00 00 c7 45 d4 0f 00 00 00 c7 45 d8 0b 00 00 00 c7 45 dc 01 00 00 00 c7 45 e0 0a 00 00 00 c7 45 e4 0d 00 00 00 c7 45 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_XZ_2147903589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.XZ!MTB"
        threat_id = "2147903589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 00 8b 40 10 c3}  //weight: 1, accuracy: High
        $x_1_2 = "libEGL.dll.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_QL_2147903623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.QL!MTB"
        threat_id = "2147903623"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f8 01 15 ?? ?? ?? ?? c1 c0 ?? e8 ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 41 e8 ?? ?? ?? ?? 87 f7 01 05 ?? ?? ?? ?? 81 f6 ?? ?? ?? ?? e8 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 25 ?? ?? ?? ?? ?? ?? ?? ?? 4f 81 f7 ?? ?? ?? ?? 89 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_JW_2147904683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.JW!MTB"
        threat_id = "2147904683"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 1c 07 83 c7 ?? 0f af 5e ?? 8b 46 ?? 8b d3 c1 ea ?? 88 14 01 ff 46 ?? 8b 4e}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c1 01 86 ?? ?? ?? ?? b8 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b 86 ?? ?? ?? ?? 2b 86 ?? ?? ?? ?? 01 81 ?? ?? ?? ?? c7 06 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b 88 ?? ?? ?? ?? 49 01 8e ?? ?? ?? ?? 81 ff ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_KM_2147905612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.KM!MTB"
        threat_id = "2147905612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 08 8d 55 ?? 8b 45 ?? 01 d0 0f b6 00 31 c1 89 ca 8d 8d ?? ?? ?? ?? 8b 45 ?? 01 c8 88 10 83 45 ?? ?? 83 45 ?? ?? 8b 45 ?? 3d ?? ?? ?? ?? 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_ACL_2147905704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.ACL!MTB"
        threat_id = "2147905704"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 03 6a 00 6a 00 68 28 03 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_KO_2147905991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.KO!MTB"
        threat_id = "2147905991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c2 83 e2 ?? 8a 14 11 8b 4d ?? 32 14 01 88 14 03 40 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_CCIB_2147906100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.CCIB!MTB"
        threat_id = "2147906100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 d1 83 e1 ?? 8a 0c 0e 8b 75 ?? 32 0c 16 88 0c 10 42 39 d3 75 e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_KQ_2147906449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.KQ!MTB"
        threat_id = "2147906449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 85 a0 f9 ?? ?? 40 89 85 ?? ?? ?? ?? 81 bd ?? ?? ?? ?? ?? ?? ?? ?? 73 ?? 8b 85 ?? ?? ?? ?? 0f be 8c 05 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 99 f7 bd ?? ?? ?? ?? 0f be 44 15 ?? 33 c8 8b 85 ?? ?? ?? ?? 88 8c 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_ACO_2147907009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.ACO!MTB"
        threat_id = "2147907009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 30 68 dc 41 40 00 b9 20 60 40 00 e8 ?? ?? ?? ?? c7 45 fc 00 00 00 00 b9 38 60 40 00 6a 30}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 05 60 60 40 00 00 00 00 00 c7 05 64 60 40 00 0f 00 00 00 c6 05 50 60 40 00 00 e8 ?? ?? ?? ?? c6 45 fc 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_TO_2147907445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.TO!MTB"
        threat_id = "2147907445"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 07 47 84 c0 75 ?? 2b f9 33 f6 8b c6 ?? f7 ff 8a 44 15 ?? 32 84 35 ?? ?? ?? ?? 88 84 35 ?? ?? ?? ?? 0f b6 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_COF_2147909855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.COF!MTB"
        threat_id = "2147909855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d3 c1 ea 08 88 14 08 b9 d6 67 17 00 ff 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 35 ca 2c 10 00 0f af 87 b4 00 00 00 89 87 b4 00 00 00 8b 87 fc 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {03 87 c8 00 00 00 09 87 a4 00 00 00 a1 ?? ?? ?? ?? 2b 88 b4 00 00 00 2b 8f c0 00 00 00 01 8f 0c 01 00 00 a1 ?? ?? ?? ?? 8b 8f 88 00 00 00 88 1c 08 ff 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 87 c0 00 00 00 81 fd 58 23 00 00 0f 8c 50 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_FK_2147910137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.FK!MTB"
        threat_id = "2147910137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 07 47 84 c0 75}  //weight: 1, accuracy: High
        $x_1_2 = {8b c6 99 f7 ff 8a 44 15 ?? 32 84 35 ?? ?? ?? ?? 88 84 35 ?? ?? ?? ?? 0f b6 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_AST_2147910325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.AST!MTB"
        threat_id = "2147910325"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e1 c1 ea 04 8b ca c1 e1 04 03 ca 8b c6 8d 7f 06 2b c1 8b 4d ?? 03 c3 83 c3 06 0f b6 44 05 ?? 32 44 39 fa 88 47 ff 81 fb 00 10 05 00 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_CCIH_2147910381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.CCIH!MTB"
        threat_id = "2147910381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c3 0f b6 44 05 ?? 32 04 39 8b 4d ?? 88 07 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_YBD_2147910810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.YBD!MTB"
        threat_id = "2147910810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 d1 8a 4c 24 1b 81 e2 ?? ?? ?? ?? 02 d9 88 5c 24 14 8a 54 14 ?? 32 d1 8b 4c 24 14 81 e1 ?? ?? ?? ?? 88 14 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_IF_2147911408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.IF!MTB"
        threat_id = "2147911408"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c2 83 e2 ?? 8a 14 11 8b 4d ?? 32 14 01 88 14 06 40 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_SIH_2147911630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.SIH!MTB"
        threat_id = "2147911630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 94 c1 83 c7 04 03 d1 89 4d ec 8b 4d e8 89 54 8e 08 02 cb 0f b6 c9 02 c1 02 45 f0 0f b6 c0 0f b6 4c 86 08 30 4f fe}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_PB_2147911722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.PB!MTB"
        threat_id = "2147911722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 85 48 f8 ff ff 83 ec 18 c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 ff d0}  //weight: 1, accuracy: High
        $x_1_2 = "minimaaccusamusnihilvoluptaset90.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_PAED_2147912211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.PAED!MTB"
        threat_id = "2147912211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 0f b6 04 0e 41 31 f8 44 88 04 0a 8d 48 01 39 cb 7e 78 48 63 c9 44 0f b6 04 0e 41 31 f8 44 88 04 0a 8d 48 02 39 cb 7e 62 48 63 c9 44 0f b6 04 0e 41 31 f8 44 88 04 0a 8d 48 03}  //weight: 1, accuracy: High
        $x_1_2 = {48 63 c9 44 0f b6 04 0e 41 31 f8 44 88 04 0a 8d 48 04 39 cb 7e 36 48 63 c9 44 0f b6 04 0e 41 31 f8 44 88 04 0a 8d 48 05 39 cb 7e 20 48 63 c9 83 c0 06 44 0f b6 04 0e 41 31 f8 44 88 04 0a 39 c3 7e 0a 48 98 40 32 3c 06 40 88 3c 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_YBJ_2147912537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.YBJ!MTB"
        threat_id = "2147912537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 c3 32 9f ?? ?? ?? ?? 8b 44 24 30 88 58 03 89 f7 c1 ef 18 8b 44 24 04 8b 5c 24 08 8b 84 03 ec 01 00 00 89 c3 c1 eb 18 32 9f ?? ?? ?? ?? 8b 7c 24 30}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_YBK_2147912750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.YBK!MTB"
        threat_id = "2147912750"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 55 f0 89 75 ec 01 ca 0f b6 04 10 32 04 13 8b 5d d8 88 44 33 ff 89 d9}  //weight: 10, accuracy: High
        $x_2_2 = {89 ce 8b 4d ec 8b 5d d4 0f b6 04 10 83 c3 02 32 44 17 01 88 04 0e 8b 75 d0 83 c1 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_PM_2147912962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.PM!MTB"
        threat_id = "2147912962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d8 0f b6 44 1e ?? 88 44 3e ?? 88 4c 1e ?? 02 c8 0f b6 c1 8b 4d ?? 8a 44 30 ?? 32 44 11 ?? 83 6d ?? ?? 88 42 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_IJ_2147913340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.IJ!MTB"
        threat_id = "2147913340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 04 0e 83 e0 ?? 0f b6 80 ?? ?? ?? ?? 32 42 ?? 88 41 ?? 8d 04 0b 83 e0 ?? 8d 49 ?? 0f b6 80 ?? ?? ?? ?? 32 02 88 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_YBN_2147913878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.YBN!MTB"
        threat_id = "2147913878"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c1 8b 45 d8 0f af 45 ?? 29 c1 89 c8 01 c2 8b 45 d0 01 d0 0f b6 44 05 ?? 31 f0 88 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_PT_2147914038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.PT!MTB"
        threat_id = "2147914038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cd c1 ea ?? 6b c2 ?? 2b c8 03 ce 8a 44 0c ?? 32 86 ?? ?? ?? ?? 46 88 47 ?? 81 fe ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_CAM_2147914302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.CAM!MTB"
        threat_id = "2147914302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 31 41 04 a1 ?? ?? ?? ?? 8b 88 88 00 00 00 2b 88 dc 00 00 00 8b 86 c0 00 00 00 81 c1 42 77 04 00 03 86 9c 00 00 00 01 8e b8 00 00 00 83 f0 4a 0f af 86 fc 00 00 00 89 86 fc 00 00 00 a1 ?? ?? ?? ?? 3b 50 38 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_CBM_2147914303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.CBM!MTB"
        threat_id = "2147914303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 86 00 01 00 00 35 5a 35 0d 00 0f af 81 00 01 00 00 89 81 00 01 00 00 8b 46 2c 01 86 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 88 f0 00 00 00 8b 46 58 40 03 c1 0f af 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 05 84 1f ed ff 01 86 98 00 00 00 81 fd b8 b8 01 00 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_YBO_2147914320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.YBO!MTB"
        threat_id = "2147914320"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 06 2d fa e1 15 00 01 86 20 01 00 00 8b 46 44 8b d3 33 86 20 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_MIA_2147914653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.MIA!MTB"
        threat_id = "2147914653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 0f b6 c0 0f b6 44 04 10 30 81 ?? ?? ?? ?? 8d 83 ?? ?? ?? ?? 03 c1 0f b6 c0 0f b6 44 04 10 30 81 ?? ?? ?? ?? 8b 44 24 0c 8d 80 ?? ?? ?? ?? 03 c1 0f b6 c0 0f b6 44 04 10 30 81 ?? ?? ?? ?? 83 c1 06 81 f9 d8 06 00 00 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_GXL_2147916720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.GXL!MTB"
        threat_id = "2147916720"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f be 02 83 f0 ?? 8b 4d ?? 03 4d ?? 88 01}  //weight: 5, accuracy: Low
        $x_5_2 = {03 fa d0 ba ?? ?? ?? ?? 3c c2 70 02 5d 55 ec ?? ?? fa fa 34 fa}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_UTA_2147917155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.UTA!MTB"
        threat_id = "2147917155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 4b 08 89 53 04 89 5c 24 0c 89 44 24 08 89 4c 24 04 89 14 24 ff 15 14 81 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_AMMH_2147917717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.AMMH!MTB"
        threat_id = "2147917717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c2 83 e2 ?? 8a 14 11 8b 4d ?? 32 14 01 8b 4d ?? 88 14 01 40 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_PS_2147918021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.PS!MTB"
        threat_id = "2147918021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" ascii //weight: 2
        $x_1_2 = {c7 44 24 24 65 00 00 00 c7 44 24 20 70 00 00 00 c7 44 24 1c 69 00 00 00 c7 44 24 18 70 00 00 00 c7 44 24 14 5c 00 00 00 c7 44 24 10 2e 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_UFC_2147919877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.UFC!MTB"
        threat_id = "2147919877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {46 0f b6 84 34 70 01 00 00 88 84 14 ?? ?? ?? ?? 88 8c 34 70 01 00 00 0f b6 84 14 70 01 00 00 0f b6 c9 03 c8 0f b6 c1 8b 8c 24 88 00 00 00 0f b6 84 04 70 01 00 00 30 04 39 47 3b bc 24 a8 00 00 00 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_AT_2147920417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.AT!MTB"
        threat_id = "2147920417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 21 6d 01 35 65 0c 6f 66 65 0c 6f 66 65 0c 6f 66 b6 7e 6c 67 74 0c 6f 66 b6 7e 6a 67 c5 0c 6f 66 b6 7e 6b 67 72 0c 6f 66 71 73 6a 67 42 0c 6f 66 c1 72 6b 67 6a 0c 6f 66 c1 72 6c 67 7d 0c 6f 66 c1 72 6a 67 34 0c 6f 66 b6 7e 6e 67 60 0c 6f 66 65 0c 6e 66 e3 0c 6f 66 71 73 66 67 67 0c 6f 66 71 73 6f 67 64 0c 6f 66 71 73 90 66 64 0c 6f 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_AMK_2147923694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.AMK!MTB"
        threat_id = "2147923694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 0f ef c8 0f 11 88 28 40 00 10 0f 10 80 38 40 00 10 0f 28 ca 66 0f ef c2 0f 11 80 38 40 00 10 0f 10 80 48 40 00 10 66 0f ef c8 0f 11 88 48 40 00 10 0f 10 80 58 40 00 10}  //weight: 1, accuracy: High
        $x_1_2 = {80 b0 28 40 00 10 e2 40 3d 10 38 03 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_MNO_2147924900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.MNO!MTB"
        threat_id = "2147924900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 f0 88 03 83 45 f0 01 8b 45 b4 39 45 f0}  //weight: 2, accuracy: High
        $x_1_2 = "Dc))#U*MHMnDa$8>+#P" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_GE_2147925880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.GE!MTB"
        threat_id = "2147925880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.AesDecryptByECB" ascii //weight: 1
        $x_1_2 = "main.PKCS7UNPadding" ascii //weight: 1
        $x_1_3 = "main.closeWindows" ascii //weight: 1
        $x_1_4 = "runtime.sysReserve" ascii //weight: 1
        $x_1_5 = "runtime.badctxt" ascii //weight: 1
        $x_1_6 = "runtime.allgadd" ascii //weight: 1
        $x_1_7 = "runtime.traceShuttingDown" ascii //weight: 1
        $x_1_8 = "runtime.traceLocker.GoSched" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_PU_2147926352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.PU!MTB"
        threat_id = "2147926352"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 aa 26 00 00 31 d2 [0-10] c7 44 24 ?? 5c 00 00 00 c7 44 24 ?? 65 00 00 00 c7 44 24 ?? 70 00 00 00 c7 44 24 ?? 69 00 00 00 c7 44 24 ?? 70 00 00 00 [0-4] c7 44 24 ?? 5c 00 00 00 c7 44 24 ?? 2e 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_ZA_2147927464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.ZA!MTB"
        threat_id = "2147927464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 15 dc 64 07 00 48 8d 44 24 40 48 8b 0d d8 64 07 00 33 db 48 89 5c 24 30 45 33 c9 48 89 5c 24 28 89 5c 24 40 44 8d 43 01 48 89 44 24 20}  //weight: 1, accuracy: High
        $x_1_2 = {48 f7 e9 48 03 d1 48 c1 fa 18 48 8b fa 48 c1 ef 3f 48 03 fa 49 03 f8}  //weight: 1, accuracy: High
        $x_1_3 = {b8 0d 00 00 00 66 89 45 8f 48 89 7c 24 20 4c 8d 4d 97 44 8d 40 f4 48 8d 55 8f 49 8b cc}  //weight: 1, accuracy: High
        $x_1_4 = {48 89 7c 24 20 4c 8d 4d 80 45 33 c0 48 8b d7 48 8d 4c 24 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_GC_2147928270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.GC!MTB"
        threat_id = "2147928270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 d2 89 c8 bb 15 00 00 00 f7 f3 0f b6 81 00 f0 60 00 0f b6 9a c4 03 56 00 31 d8 88 81 00 f0 60 00 41 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_GTT_2147935431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.GTT!MTB"
        threat_id = "2147935431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b7 04 c8 0f b7 cb 0b c1 0f b6 4c 24 ?? 0b c2 33 d2 f7 f1 8b 4c 24 ?? 31 04 37 8d 43 ?? 0f b7 c0 03 c0 5f 5e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_OTV_2147941814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.OTV!MTB"
        threat_id = "2147941814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 81 c9 00 ff ff ff 41 8b 85 ?? ?? ff ff 8b 95 f4 fd ff ff 0f b6 8c 0d ?? ?? ff ff 30 0c 10 40 89 85 f8 fd ff ff 3b c7 7c 82}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_AM_2147943815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.AM"
        threat_id = "2147943815"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 65 61 63 6f 6e 44 61 74 61 53 68 6f 72 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {42 65 61 63 6f 6e 55 73 65 54 6f 6b 65 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {42 65 61 63 6f 6e 52 65 76 65 72 74 54 6f 6b 65 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {42 65 61 63 6f 6e 43 6c 65 61 6e 75 70 50 72 6f 63 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {42 65 61 63 6f 6e 49 73 41 64 6d 69 6e 00}  //weight: 1, accuracy: High
        $x_1_6 = {42 65 61 63 6f 6e 47 65 74 53 70 61 77 6e 54 6f 00}  //weight: 1, accuracy: High
        $x_1_7 = {42 65 61 63 6f 6e 53 70 61 77 6e 54 65 6d 70 6f 72 61 72 79 50 72 6f 63 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_8 = {42 65 61 63 6f 6e 49 6e 6a 65 63 74 50 72 6f 63 65 73 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_CobaltStrike_CE_2147943816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.CE"
        threat_id = "2147943816"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 65 61 63 6f 6e 44 61 74 61 50 61 72 73 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {42 65 61 63 6f 6e 44 61 74 61 49 6e 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {42 65 61 63 6f 6e 44 61 74 61 4c 65 6e 67 74 68 00}  //weight: 1, accuracy: High
        $x_1_4 = {42 65 61 63 6f 6e 49 6e 6a 65 63 74 54 65 6d 70 6f 72 61 72 79 50 72 6f 63 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {42 65 61 63 6f 6e 44 61 74 61 45 78 74 72 61 63 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {42 65 61 63 6f 6e 4f 75 74 70 75 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {42 65 61 63 6f 6e 46 6f 72 6d 61 74 41 70 70 65 6e 64 00}  //weight: 1, accuracy: High
        $x_1_8 = {42 65 61 63 6f 6e 46 6f 72 6d 61 74 54 6f 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_CobaltStrike_MK_2147943817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.MK"
        threat_id = "2147943817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 65 61 63 6f 6e 46 6f 72 6d 61 74 41 6c 6c 6f 63 00}  //weight: 1, accuracy: High
        $x_1_2 = {42 65 61 63 6f 6e 46 6f 72 6d 61 74 52 65 73 65 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {42 65 61 63 6f 6e 46 6f 72 6d 61 74 46 72 65 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {42 65 61 63 6f 6e 46 6f 72 6d 61 74 50 72 69 6e 74 66 00}  //weight: 1, accuracy: High
        $x_1_5 = {42 65 61 63 6f 6e 46 6f 72 6d 61 74 49 6e 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_MHI_2147944306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.MHI!MTB"
        threat_id = "2147944306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 75 c8 8b 7d cc 29 f7 89 d8 31 d2 f7 f7 0f b6 14 16 32 14 19 88 95 ?? ?? ?? ?? 8b 45 d8 3b 45 dc 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_GDF_2147944855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.GDF!MTB"
        threat_id = "2147944855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 0c 89 45 ?? 89 65 ec 68 ?? ?? ?? ?? ff 75 fc 33 c0 ff 15 ?? ?? ?? ?? ?? ?? 39 65 ec}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrike_UWW_2147946263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrike.UWW!MTB"
        threat_id = "2147946263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {99 35 36 c7 21 a3 66 a3 ?? ?? ?? ?? 0f be 05 ?? ?? ?? ?? 0f b6 4d fd 0f b7 15 ?? ?? ?? ?? 0b ca 03 c1 88 45 fd 8b 45 8c 05 8b 00 00 00 89 85 ?? fd ff ff b9 5d 00 00 00 66 89 0d}  //weight: 4, accuracy: Low
        $x_5_2 = {2b c8 8b 85 70 fe ff ff 1b c2 33 f1 33 f8 89 75 b4 89 7d b8 0f bf 4d e4 03 0d ?? ?? ?? ?? 0f bf 55 e4 0b d1 66 89 55 e4 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

