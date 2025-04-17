rule Trojan_Win32_Qakbot_A_2147734746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.A"
        threat_id = "2147734746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 00 33 00 30 00 38 00}  //weight: 1, accuracy: High
        $x_1_2 = {03 00 33 00 31 00 31 00}  //weight: 1, accuracy: High
        $x_1_3 = {03 00 31 00 31 00 38 00}  //weight: 1, accuracy: High
        $x_1_4 = {03 00 35 00 32 00 34 00}  //weight: 1, accuracy: High
        $x_10_5 = {01 23 45 67 c7 44 24 ?? 89 ab cd ef c7 44 24 ?? fe dc ba 98 c7 44 24}  //weight: 10, accuracy: Low
        $x_10_6 = {03 ce 03 c1 33 d2 6a ?? 5b f7 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? 46}  //weight: 10, accuracy: Low
        $x_10_7 = {48 f7 d8 1b c0 25 ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_SD_2147740376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SD!MTB"
        threat_id = "2147740376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 48 3c 81 f7 ?? ?? ?? ?? 0f af fb 8d 41 ?? f7 d0 03 fa 8b 52 ?? 4a 03 d1 85 d0}  //weight: 1, accuracy: Low
        $x_1_2 = {33 cb 42 89 4e ?? 69 85 ?? ?? ?? ?? ?? ?? ?? ?? 3b d0 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_E_2147742203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.E"
        threat_id = "2147742203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "emtn\\pldrss.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GG_2147742543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GG!MTB"
        threat_id = "2147742543"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 02 8b 45 d8 03 45 b0 03 45 e8 89 45 b4 6a 00 e8 ?? ?? ?? ?? 8b 5d b4 2b d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 ec 31 18 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GG_2147742543_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GG!MTB"
        threat_id = "2147742543"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 5a 8a 44 ?? ?? 8a 4c ?? ?? f6 e1 [0-30] 50 45}  //weight: 1, accuracy: Low
        $x_1_2 = {32 0c 02 8b ?? ?? ?? 88 0c 30 8b ?? ?? ?? 8a ?? ?? ?? 32 ?? ?? ?? 88 ?? ?? ?? 83 ?? 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GG_2147742543_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GG!MTB"
        threat_id = "2147742543"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c1 8b 45 [0-2] fc f3 a4 57 c7 04 [0-6] 59 55 33 2c [0-2] 0b ab [0-4] 83 e0 00 31 e8 5d 56 81 04 [0-6] 29 34 [0-2] 8f 83 [0-4] 21 8b [0-4] 6a 00 31 2c [0-2] 50 5d 03 ab [0-4] 89 e8 5d ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GG_2147742543_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GG!MTB"
        threat_id = "2147742543"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb f1 32 01 00 bb f1 32 01 00 bb f1 32 01 00 bb f1 32 01 00 bb f1 32 01 00 bb f1 32 01 00 bb f1 32 01 00 bb f1 32 01 00 bb f1 32 01 00 bb f1 32 01 00 33 05 [0-4] 8b c8 8b d1 89 15 [0-4] a1 [0-4] 8b 0d [0-4] 89 08 5f 5b 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GG_2147742543_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GG!MTB"
        threat_id = "2147742543"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 06 88 04 [0-2] 8b 0d [0-4] 83 [0-2] 01 89 0d [0-4] eb [0-2] 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d2 8b d2 8b d2 [0-30] a1 [0-4] a3 [0-4] a1 [0-4] 8b d8 a1 [0-4] 33 d9 c7 05 [0-4] 00 00 00 00 01 1d [0-4] a1 [0-4] 8b 0d [0-4] 89 08 5b 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GG_2147742543_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GG!MTB"
        threat_id = "2147742543"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "stager_1.dll" ascii //weight: 10
        $x_10_2 = "RegisterServer" ascii //weight: 10
        $x_1_3 = "GetCapture" ascii //weight: 1
        $x_1_4 = "GetAsyncKeyState" ascii //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "VirtualProtect" ascii //weight: 1
        $x_1_7 = "GetActiveWindow" ascii //weight: 1
        $x_1_8 = "GetCurrentThreadId" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GG_2147742543_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GG!MTB"
        threat_id = "2147742543"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "stager_1.dll" ascii //weight: 10
        $x_10_2 = "DllRegisterServer" ascii //weight: 10
        $x_1_3 = "SELECT * FROM AntiVirusProduct" ascii //weight: 1
        $x_1_4 = "LookupAccountSidW" ascii //weight: 1
        $x_1_5 = "LookupAccountNameW" ascii //weight: 1
        $x_1_6 = "winsta0\\default" ascii //weight: 1
        $x_1_7 = "memset" ascii //weight: 1
        $x_1_8 = "GetUserProfileDirectoryW" ascii //weight: 1
        $x_1_9 = "USERPROFILE" ascii //weight: 1
        $x_1_10 = "OpenProcessToken" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GG_2147742543_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GG!MTB"
        threat_id = "2147742543"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "facebook.com/login" ascii //weight: 10
        $x_1_2 = "very big postdata %u bytes" ascii //weight: 1
        $x_1_3 = "pid=[" ascii //weight: 1
        $x_1_4 = "cookie=[" ascii //weight: 1
        $x_1_5 = "exe=[" ascii //weight: 1
        $x_1_6 = "ua=[" ascii //weight: 1
        $x_1_7 = "%u.%u.%u.%u" ascii //weight: 1
        $x_1_8 = "PASS" ascii //weight: 1
        $x_1_9 = "http://" ascii //weight: 1
        $x_1_10 = "ESCAPE" ascii //weight: 1
        $x_1_11 = "BACKSP" ascii //weight: 1
        $x_1_12 = "<%02X>" ascii //weight: 1
        $x_1_13 = "Mozilla\\Firefox" ascii //weight: 1
        $x_1_14 = ".jpeg" ascii //weight: 1
        $x_1_15 = "url=[" ascii //weight: 1
        $x_1_16 = "GetKeyboardState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 13 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_BS_2147742796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BS!MTB"
        threat_id = "2147742796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b f2 71 89 cf 01 f7 6b f2 71 89 cb 01 f3 83 c3 6d 6b f2 71 89 44 24 30 89 c8 01 f0 83 c0 0d 8b 00 6b f2 71 01 f1 83 c1 11 8b 09 33 0b 8b 74 24 78 89 f3 03 5c 24 7c 89 44 24 2c 8b 44 24 30 2b 07 8b 7c 24 2c 01 c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BS_2147742796_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BS!MTB"
        threat_id = "2147742796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e9 15 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? a3}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 00 8b 65 ?? 58 8b e8 8b 15 ?? ?? ?? ?? 52 8b 15 ?? ?? ?? ?? 52 8b 15 ?? ?? ?? ?? ff e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BS_2147742796_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BS!MTB"
        threat_id = "2147742796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 11 44 24 04 8d 44 24 04 50 51 01 f9 ff d1 85 ff 74 ?? b9 ?? ?? ?? ?? 03 4c 24 08 6a 40 51 8b 7c 24 44 ff 77 20 6a 00 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = "DrawThemeIcon" ascii //weight: 1
        $x_1_3 = "mfixautoutil4.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BS_2147742796_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BS!MTB"
        threat_id = "2147742796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 d8 8b 45 ec 31 18 68 [0-4] e8 [0-4] 8b d8 8b 45 e8 83 c0 04 03 d8 68 [0-4] e8 [0-4] 2b d8 68 [0-4] e8 [0-4] 03 d8 68 [0-4] e8 [0-4] 2b d8 89 5d e8 68 [0-4] e8 [0-4] 8b d8 8b 45 ec 83 c0 04 03 d8 68 [0-4] e8 [0-4] 2b d8 89 5d ec 8b 45 e8 3b 45 e4 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BS_2147742796_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BS!MTB"
        threat_id = "2147742796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e9 01 89 0d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 83 c1 01 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 31 0d ?? ?? ?? ?? 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02}  //weight: 1, accuracy: Low
        $x_1_2 = {03 f0 8b 55 ?? 03 55 ?? 8b 45 ?? 8b 4d ?? 8a 0c 31 88 0c 10 8b 55 ?? 83 c2 01 89 55 ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BS_2147742796_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BS!MTB"
        threat_id = "2147742796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 fe 81 e6 ff 00 00 00 8b 7d ?? 8a 0c 37 8b 75 ?? 8b 7d ?? 32 0c 3e 8b 75 ?? 88 0c 3e 66 c7 45 ?? c5 b4 83 c7 01 8b 75 ?? 39 f7}  //weight: 1, accuracy: Low
        $x_1_2 = {89 14 24 8b 54 24 ?? 8a 0c 11 31 de 89 74 24 ?? 8b 74 24 ?? 8b 5c 24 ?? 32 0c 1e 8b 54 24 ?? 8b 74 24 ?? 88 0c 32}  //weight: 1, accuracy: Low
        $x_1_3 = {01 d8 8b 5c 24 ?? 8a 14 33 88 c6 0f b6 c6 8b 74 24 ?? 8a 34 06 30 d6 8b 44 24 ?? 89 84 24 ?? ?? ?? ?? 8b 44 24 1c 89 84 24 ?? ?? ?? ?? 8b 44 24 ?? 88 34 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qakbot_S_2147744162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.S!MSR"
        threat_id = "2147744162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\ms-player\\pr032\\brmDsd.pdb" ascii //weight: 1
        $x_1_2 = "W14,ERahasChrome" ascii //weight: 1
        $x_1_3 = "Command (%f file, %a akelpad directory)" wide //weight: 1
        $x_1_4 = "Select checkbox for plugin autoload" wide //weight: 1
        $x_1_5 = "yindependentalsoforUidigital" ascii //weight: 1
        $x_1_6 = "DeletePrinterDriverExW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DSK_2147744950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DSK!MTB"
        threat_id = "2147744950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 44 24 50 8b 4c 24 60 89 ca 81 c2 b3 d7 b3 9a 89 54 24 04 99 8b 74 24 04 f7 fe 89 d0 8b 7c 24 14 8a 1c 17 8b 74 24 44 88 1e 8a 5c 24 4f 88 1c 17}  //weight: 2, accuracy: High
        $x_2_2 = {8b 44 24 18 0d c6 1c a1 4e 01 f2 88 d7 0f b6 d7 8b 74 24 20 89 74 24 74 89 44 24 70 8a 7c 24 6b 80 c7 a0 8b 44 24 14 8a 04 10 30 d8 88 7c 24 6b 8b 54 24 28 88 04 3a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PDSK_2147744952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PDSK!MTB"
        threat_id = "2147744952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 1c 01 8b 44 24 24 0f b6 14 10 01 fa 88 d7 0f b6 d7 8a 3c 10 30 df 8b 54 24 44}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GA_2147747950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GA!MTB"
        threat_id = "2147747950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "r:\\md-proj\\prdyjf\\rtc32.pdb" ascii //weight: 1
        $x_1_2 = {d0 2d 6b 65 1c c0 d3 0b bd fd 13 89 21 41 72 eb 22 e1 79 03 b7 6d 0c 64 76 f4 3d c0 55 44 62}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GA_2147747950_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GA!MTB"
        threat_id = "2147747950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 02 8b 45 c4 03 45 a4 03 45 9c 2b 45 9c 89 45 a0 8b 45 a0 03 45 9c 2b 45 9c 8b 55 d8 33 02 89 45 a0 8b 45 a0 03 45 9c 2b 45 9c 8b 55 d8 89 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GA_2147747950_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GA!MTB"
        threat_id = "2147747950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 c1 2b c3 83 c0 ?? a3 [0-4] 8b 06 05 [0-4] 89 06 83 c6 04 a3 [0-4] 0f b6 c1 66 03 05 [0-4] 66 03 c2 89 74 24 ?? 66 03 44 24 ?? 8b f2 66 03 f8 83 6c 24 ?? 01 66 89 7c 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GA_2147747950_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GA!MTB"
        threat_id = "2147747950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 00 8b d9 2b 5c 24 ?? 05 ?? ?? ?? ?? 52 81 c3 a6 eb 00 00 a3 ?? ?? ?? ?? 51 89 1d ?? ?? ?? ?? 8b 5c 24 ?? 6a 00 ff 74 24 ?? 89 03 e8 ?? ?? ?? ?? 8b c8 8b c3 8b 1d ?? ?? ?? ?? 83 c0 04 83 6c 24 ?? 01 89 44 24 ?? 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GA_2147747950_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GA!MTB"
        threat_id = "2147747950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {ac 68 04 f1 07 10 c3}  //weight: 5, accuracy: High
        $x_5_2 = {34 43 68 f8 a5 08 10 c3}  //weight: 5, accuracy: High
        $x_5_3 = {68 8a d6 07 10 68 8a d6 07 10 b8 69 2c 08 10 ff d0}  //weight: 5, accuracy: High
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "VirtualProtectEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GA_2147747950_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GA!MTB"
        threat_id = "2147747950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 40 00 00 00 [0-4] 00 ff 75 [0-4] 68 00 10 00 00 [0-6] 00 ff 75 [0-4] 57 83 [0-2] 00 31 [0-2] ff 93}  //weight: 1, accuracy: Low
        $x_1_2 = {fc f3 a4 b9 ff ff [0-2] ff b3 [0-4] 8f 45 [0-2] ff 75 [0-2] 58 68 [0-4] 8f 83 [0-4] 21 8b [0-4] 57 8b bb [0-4] 50 8f 45 [0-2] 01 7d [0-2] ff 75 [0-2] 58 5f ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GA_2147747950_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GA!MTB"
        threat_id = "2147747950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "b196b287-bab4-101a-b69c-00aa00341d07" ascii //weight: 1
        $x_1_2 = {03 f0 8b 45 ?? 03 30 8b 4d ?? 89 31 8b 55 ?? 8b 02 2d ?? ?? 00 00 8b 4d ?? 89 01 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 0c 32 88 0c 38 8b 55 ?? 83 c2 ?? 89 55 [0-6] 5f 5e 8b e5 5d c3 28 00 03 45 ?? 8b 55}  //weight: 1, accuracy: Low
        $x_1_4 = {8b ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 ff 00 04 01 01 01 01 31 32 30 33 [0-200] a1 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 01 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Qakbot_GA_2147747950_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GA!MTB"
        threat_id = "2147747950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "stager_1.dll" ascii //weight: 10
        $x_10_2 = "DllRegisterServer" ascii //weight: 10
        $x_1_3 = "SELECT * FROM AntiVirusProduct" ascii //weight: 1
        $x_1_4 = "LookupAccountSidW" ascii //weight: 1
        $x_1_5 = "LookupAccountNameW" ascii //weight: 1
        $x_1_6 = "winsta0\\default" ascii //weight: 1
        $x_1_7 = "memset" ascii //weight: 1
        $x_1_8 = "GetUserProfileDirectoryW" ascii //weight: 1
        $x_1_9 = "USERPROFILE" ascii //weight: 1
        $x_1_10 = "OpenProcessToken" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GA_2147747950_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GA!MTB"
        threat_id = "2147747950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "VirtualAlloc" ascii //weight: 1
        $x_1_2 = "VirtualAllocEx" ascii //weight: 1
        $x_1_3 = "b196b287-bab4-101a-b69c-00aa00341d07" ascii //weight: 1
        $x_1_4 = "RegOpenKeyA" ascii //weight: 1
        $x_10_5 = {03 f0 8b 45 ?? 03 30 8b 4d ?? 89 31 8b 55 ?? 8b 02 2d bc 01 00 00 8b 4d ?? 89 01 5e 8b e5 5d c3}  //weight: 10, accuracy: Low
        $x_10_6 = {8a 0c 32 88 0c 38 8b 55 ?? 83 c2 ?? 89 55 ?? eb ?? 5f 5e 8b e5 5d c3}  //weight: 10, accuracy: Low
        $x_10_7 = {8b ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 ff 00 04 01 01 01 01 31 32 30 33 [0-200] a1 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 01 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_DAA_2147748489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DAA!MTB"
        threat_id = "2147748489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 5c 24 23 80 f3 ?? 89 44 24 14 8b 44 24 28 01 f0 01 ca 88 5c 24 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 dc 8b 4d e8 8a 14 01 8b 75 e4 88 14 06 83 c0 01 c7 45 f0 ?? ?? ?? ?? 8b 7d ec 39 f8 89 45 dc 74 cc eb db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_JL_2147751266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.JL!MTB"
        threat_id = "2147751266"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ec 51 c7 45 ?? ?? ?? ?? ?? c7 45 00 01 c7 45 00 01 c7 45 00 01 c7 45 00 01 c7 45 00 01 c7 45 00 01 c7 45 00 01 c7 45 00 01 c7 45 00 01 c7 45 00 01 c7 45 00 01 c7 45 00 01 c7 45 00 01 c7 45 00 01 c7 45 00 01 c7 45 00 01 c7 45 00 01 c7 45 00 01}  //weight: 1, accuracy: Low
        $x_1_2 = {03 01 8b 55 ?? 89 02 8b 45 00 8b 08 81 e9 ?? ?? ?? ?? 8b 55 00 89 0a 25 00 8d 84 02 02 8b 4d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PI_2147751584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PI!MTB"
        threat_id = "2147751584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "e118de81b30131d6cc33a15402731037" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PI_2147751584_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PI!MTB"
        threat_id = "2147751584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 57 a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 89 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 8b 02 a3 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 83 e9 01 89 0d ?? ?? ?? 00 8b 0d ?? ?? ?? 00 83 c1 01 a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 a1 ?? ?? ?? 00 31 0d ?? ?? ?? 00 8b ff c7 05 ?? ?? ?? 00 00 00 00 00 a1 ?? ?? ?? 00 01 05 ?? ?? ?? 00 8b ff 8b 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 89 02 5f 5d c3}  //weight: 10, accuracy: Low
        $x_1_2 = {8b 45 fc 3b 05 ?? ?? ?? 00 72 ?? eb ?? eb ?? 8b 4d fc 89 4d ?? 8b 15 ?? ?? ?? 00 03 55 fc 89 15 ?? ?? ?? 00 8b 45 ?? 89 45 ?? 8b 4d ?? 51 6a 2d e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_KMG_2147752816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.KMG!MTB"
        threat_id = "2147752816"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e9 15 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? b9 01 00 00 00 85 c9 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DHA_2147753216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DHA!MTB"
        threat_id = "2147753216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c1 01 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 01 31 0d 01 8b ff c7 05 00 00 00 00 00 a1 01 01 05 00 8b ff 8b 15 ?? ?? ?? ?? a1 00 89 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_RGQ_2147753240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RGQ!MTB"
        threat_id = "2147753240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 ea 05 89 55 ?? 8b 45 ?? 03 45 ?? 89 45 ?? 8b 4d ?? 33 4d ?? 89 4d ?? c7 05 ?? ?? ?? ?? f4 6e e0 f7 8b 55 ?? 33 55 ?? 89 55 ?? 8b 45 ?? 2b 45 ?? 89 45 ?? 81 3d ?? ?? ?? ?? d9 02 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DHB_2147753428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DHB!MTB"
        threat_id = "2147753428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 d7 f7 d3 89 44 24 ?? 8b 44 24 ?? 0f b6 14 10 01 f2 88 d0 0f b6 d0 89 5c 24 ?? 89 7c 24 ?? 8b 74 24 ?? 8b 7c 24 ?? 8a 04 3e 8b 5c 24 ?? 32 04 13 8b 54 24 ?? 88 04 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GM_2147757137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GM!MTB"
        threat_id = "2147757137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 0e 00 00 00 ff 35 ?? ?? ?? ?? b8 9c 00 00 00 ff 35 ?? ?? ?? ?? b8 11 00 00 00 ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? b8 01 00 00 00 50 ff 25}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GM_2147757137_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GM!MTB"
        threat_id = "2147757137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ff c7 05 [0-48] 01 05 [0-48] 8b ff a1 [0-48] 8b 0d ?? ?? ?? ?? 89 08}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 11 89 15 [0-64] 8b 0d [0-200] a1 [0-32] 33 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GM_2147757137_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GM!MTB"
        threat_id = "2147757137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fc f3 a4 56 c7 04 e4 ff ff 0f 00 59 8b 83 ?? ?? ?? ?? 50 c7 04 e4 ?? ?? ?? ?? 8f 83 ?? ?? ?? ?? 21 8b ?? ?? ?? ?? 89 55 fc 89 c2 03 93 ?? ?? ?? ?? 52 8b 55 fc 8f 83 ?? ?? ?? ?? ff a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GM_2147757137_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GM!MTB"
        threat_id = "2147757137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 [0-25] 33 [0-3] c7 05 [0-4] 00 00 00 00 [0-6] 01 [0-5] a1 [0-4] 8b 0d [0-4] 89 08 ?? 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GM_2147757137_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GM!MTB"
        threat_id = "2147757137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 d8 33 18 89 5d a0 [0-50] 03 d8 8b 45 d8 89 18 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 [0-10] 8b 55 d8 83 c2 04 03 55 a4 03 c2 40 89 45 d8 8b 45 a8 3b 45 cc 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GM_2147757137_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GM!MTB"
        threat_id = "2147757137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 e4 ff ff 0f 00 59 6a 00 89 3c [0-1] 31 ff 0b bb [0-4] 89 f8 5f 50 c7 04 e4 [0-4] 8f 83 [0-4] 21 8b [0-4] 6a 00 31 34 [0-1] 50 5e 03 b3 [0-4] 89 f0 5e ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GM_2147757137_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GM!MTB"
        threat_id = "2147757137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 e4 ff ff 0f 00 59 89 75 [0-1] 31 f6 0b b3 [0-4] 89 f0 8b 75 [0-1] 68 [0-4] 8f 83 [0-4] 21 8b [0-4] 52 8b 93 [0-4] 50 8f 45 [0-1] 01 55 [0-1] ff 75 [0-1] 58 5a ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GM_2147757137_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GM!MTB"
        threat_id = "2147757137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fc f3 a4 50 c7 04 e4 ff ff 0f 00 59 89 75 [0-1] 33 75 [0-1] 33 b3 [0-4] 83 e0 00 09 f0 8b 75 [0-1] 68 [0-4] 8f 83 [0-4] 21 8b [0-4] 51 8b 8b [0-4] 50 8f 45 [0-1] 01 4d [0-1] ff 75 [0-1] 58 59 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GM_2147757137_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GM!MTB"
        threat_id = "2147757137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 04 e4 31 0c e4 ff 93 [0-4] 51 83 e1 00 31 c1 83 a3 [0-4] 00 09 8b [0-4] 59 29 c9 8f 45 [0-1] 0b 4d [0-1] 8f 45 [0-1] 8b 45 [0-1] 68 [0-4] 8f 83 [0-4] 21 8b [0-4] 51 8b 8b [0-4] 50 8f 45 [0-1] 01 4d [0-1] ff 75 [0-1] 58 59 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GM_2147757137_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GM!MTB"
        threat_id = "2147757137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d8 8b 45 ?? 83 c0 04 03 d8 [0-8] 2b d8 89 5d ?? 8b 45 ?? 83 c0 04 89 45 ?? 8b 45 ?? 3b 45 ?? 0f 82 4b 00 8b 45 ?? 03 45 ?? 8b 55 ?? 31}  //weight: 10, accuracy: Low
        $x_5_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GM_2147757137_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GM!MTB"
        threat_id = "2147757137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {99 03 04 24 13 54 24 04 83 c4 ?? 8b d0 8b 45 ?? 03 45 ?? 8b 4d ?? e8}  //weight: 5, accuracy: Low
        $x_10_2 = {2b d8 89 5d ?? 8b 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 83 45 ?? 04 8b 45}  //weight: 10, accuracy: Low
        $x_5_3 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GM_2147757137_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GM!MTB"
        threat_id = "2147757137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 af 00 01 02 a1 ?? ?? ?? ?? 83 e8 0b 03 05 ?? ?? ?? ?? a3 [0-60] 02 01 01 31 33}  //weight: 10, accuracy: Low
        $x_5_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_5_3 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 [0-5] 03 [0-5] 8b [0-5] e8}  //weight: 5, accuracy: Low
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GM_2147757137_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GM!MTB"
        threat_id = "2147757137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {99 52 50 8b 45 d4 33 d2 3b 54 24 04 75 0d 3b 04 24 5a 58 0f 87 64 00 8b 00 33 45 ?? 89 45 ?? 8b 45 ?? 8b 55 ?? 89 02}  //weight: 10, accuracy: Low
        $x_5_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_5_3 = {99 03 04 24 13 54 24 04 83 c4 ?? 8b d0 8b 45 ?? 03 45 ?? 8b 4d ?? e8}  //weight: 5, accuracy: Low
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GM_2147757137_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GM!MTB"
        threat_id = "2147757137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 00 03 45 ?? 03 d8 [0-150] 8b 45 ?? 05 ?? ?? ?? ?? 03 45 ?? 8b 15 ?? ?? ?? ?? 31 [0-150] 83 45 ?? 04 83 05 ?? ?? ?? ?? 04 8b 45 ?? 3b 45 ?? 0f 82}  //weight: 10, accuracy: Low
        $x_4_2 = {03 d8 01 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? e9}  //weight: 4, accuracy: Low
        $x_4_3 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 4, accuracy: High
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GM_2147757137_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GM!MTB"
        threat_id = "2147757137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 cc 03 45 [0-40] 2b d8 8b 45 d8 31 18 83 45 ?? 04 83 45 d8 04 8b 45 [0-90] 33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 18 00 99 52 50}  //weight: 10, accuracy: Low
        $x_10_2 = {8b d8 8b 45 cc 03 45 ?? 03 d8 [0-7] 2b d8 [0-7] 03 d8 [0-7] 2b d8 8b 45 d8 31 ?? 83 45 ?? 04 83 45 d8 04 8b 45 ?? 3b 45 d4 72}  //weight: 10, accuracy: Low
        $x_5_3 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GM_2147757137_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GM!MTB"
        threat_id = "2147757137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 10 83 45 [0-4] 04 83 45 [0-4] 04 8b 45 ?? 3b 45 af 00 01 10 8b 45 ?? 03 45 ?? 03 45 ?? 89 45 [0-60] 02 01 01 31 33}  //weight: 10, accuracy: Low
        $x_10_2 = {89 02 83 45 [0-4] 04 83 45 [0-4] 04 8b 45 ?? 3b 45 af 00 01 10 8b 45 ?? 03 45 ?? 03 45 ?? 89 45 [0-60] 02 01 01 31 33}  //weight: 10, accuracy: Low
        $x_5_3 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_5_4 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 [0-5] 03 [0-5] 8b [0-5] e8}  //weight: 5, accuracy: Low
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_PRB_2147757589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PRB!MTB"
        threat_id = "2147757589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dgeo56k87ih9k45687u9y845kuj69y84j598j38uh8t7" ascii //weight: 1
        $x_1_2 = "XYXLIJAWWFYCNAVMTC0" ascii //weight: 1
        $x_1_3 = "200616085806Z" ascii //weight: 1
        $x_1_4 = "cHdCvNcpom" wide //weight: 1
        $x_1_5 = "LypsvMDoqN" wide //weight: 1
        $x_1_6 = "LxJbAYhdYo" wide //weight: 1
        $x_1_7 = "SbHbSTvJPA" wide //weight: 1
        $x_1_8 = "DSiDlDoGMD" wide //weight: 1
        $x_1_9 = "WDVHbZxrFq" wide //weight: 1
        $x_1_10 = "jRoYWilqzE" wide //weight: 1
        $x_1_11 = "ElfqFbyMFr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MG_2147758144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MG!MTB"
        threat_id = "2147758144"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 46 34 40 0f af 46 44 89 46 44 8b 46 14 2d ?? ?? ?? ?? 31 46 18 8b 46 68 35 ?? ?? ?? ?? 29 46 48 8b 86 ?? ?? ?? ?? 09 86 ?? ?? ?? ?? 8b 86 ?? ?? ?? ?? 01 86 ?? ?? ?? ?? 81 fb ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MG_2147758144_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MG!MTB"
        threat_id = "2147758144"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {d9 fc 7a 65 d8 ba 08 00 3d bb 08 00 3d ee 66 6d dc ca 5e 69 d8 cb 47 66 83 d2 64 65 3d bb 08}  //weight: 10, accuracy: High
        $x_10_2 = {19 de 40 61 13 df 64 65 f2 ba 08 00 fe c8 6d 61 11 de 4e 69 11 de 49 00 3d bb 08 00 3d bb 08 53 e0 ce 4e 69 d1 dd 58 6f e4 d4 7c 65 cf ba 08}  //weight: 10, accuracy: High
        $x_2_3 = "GetKeyboardType" ascii //weight: 2
        $x_2_4 = "GetThreadLocale" ascii //weight: 2
        $x_2_5 = "WaitForSingleObject" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MG_2147758144_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MG!MTB"
        threat_id = "2147758144"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lcms15Fixed16toDouble" ascii //weight: 1
        $x_1_2 = "lcmsCalloc" ascii //weight: 1
        $x_1_3 = "lcmsCreateMutex" ascii //weight: 1
        $x_1_4 = "lcmsDestroyMutex" ascii //weight: 1
        $x_1_5 = "lcmsGetTransformFormatters16" ascii //weight: 1
        $x_1_6 = "lcmsLockMutex" ascii //weight: 1
        $x_1_7 = "lcmsMAT3solve" ascii //weight: 1
        $x_1_8 = "lmsCIECAM02Reverse" ascii //weight: 1
        $x_1_9 = "next" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PA_2147758189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PA!MTB"
        threat_id = "2147758189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 75 f4 03 c6 03 45 f4 8b 0d ?? ?? ?? ?? 03 4d f4 03 4d f4 03 4d f4 8b 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 8a 04 06 88 04 0a 8b 0d ?? ?? ?? ?? 83 c1 01 89 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {03 f0 8b 55 08 8b 02 2b c6 8b 4d 08 89 01 5e 8b e5 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PA_2147758189_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PA!MTB"
        threat_id = "2147758189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 80 0d 00 00 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 83 c0 04 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 99 52 50 a1 ?? ?? ?? ?? 33 d2 3b 54 24 04 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 16 89 50 08 8b 56 04 89 50 0c 8b 13 89 10 89 58 04 89 42 04 89 03 b0 01 5e 5b c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PB_2147758190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PB!MTB"
        threat_id = "2147758190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 2b fa 8b c6 8d 0c 16 83 e0 0f 8a 80 ?? ?? ?? ?? 32 04 0f 46 88 01 3b f3 72 ?? 5f 5e}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 8b c3 f7 75 ?? 8b 45 ?? 8a 04 02 32 04 0b 88 04 1f 43 83 ee 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PB_2147758190_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PB!MTB"
        threat_id = "2147758190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af f2 8b 97 ?? ?? ?? ?? 89 b7 ?? ?? ?? ?? 31 1c 82 8b 57 ?? 31 ca 8b b7 ?? ?? ?? ?? 01 f2 42 89 97 ?? ?? ?? ?? 8b 97 ?? ?? ?? ?? 2b 57 ?? 81 c2 ?? ?? ?? ?? 09 97 ?? ?? ?? ?? 8b b7 ?? ?? ?? ?? 8d 96 ?? ?? ?? ?? 0f af d6}  //weight: 1, accuracy: Low
        $x_1_2 = "DrawThemeIcon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AR_2147758267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AR!MTB"
        threat_id = "2147758267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 f0 8b 45 08 8b 08 2b ce 8b 55 08 89 0a 5e 8b e5 5d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AR_2147758267_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AR!MTB"
        threat_id = "2147758267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 8c 06 c2 5a 00 00 8b 55 08 89 0a}  //weight: 2, accuracy: High
        $x_2_2 = {8b 45 08 8b 08 2b ce 8b 55 08 89 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AR_2147758267_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AR!MTB"
        threat_id = "2147758267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 f5 30 de bc e8 98 20 0b 14 34 0a eb ba 64 a1 97 57 2c 61 4c 37 ad}  //weight: 1, accuracy: High
        $x_1_2 = {19 36 00 0b 97 37 ff 47 20 3e 8b 06}  //weight: 1, accuracy: High
        $x_1_3 = {83 74 d0 38 5f 74 da b9 51 a2 4e 4f 53 ed 38 5c 5f ef b9 5d 62 de 2e 08 7a 57}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AR_2147758267_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AR!MTB"
        threat_id = "2147758267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d f4 8b 55 fc 8d 84 0a 59 11 00 00 89 45 f0 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 55 f0 89 15 ?? ?? ?? ?? 8b 45 fc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AR_2147758267_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AR!MTB"
        threat_id = "2147758267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 8c 10 fd 8a 67 00 89 4d f8 8b 55 f8 81 ea fd 8a 67 00 89 55 f8 b8 23 5f ff ff 03 05 ?? ?? ?? ?? 8b 80 19 a1 00 00 a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AR_2147758267_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AR!MTB"
        threat_id = "2147758267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3ad75e300281231e" ascii //weight: 1
        $x_1_2 = "4f18924839bc9ec0" ascii //weight: 1
        $x_1_3 = "a0788eabd16f6497" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AR_2147758267_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AR!MTB"
        threat_id = "2147758267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 8b 45 0c 89 45 fc 8b 0d ?? ?? ?? ?? 89 4d 08 8b 55 08 8b 02 8b 4d fc 8d 94 01 c2 5a 00 00 8b 45 08 89 10}  //weight: 1, accuracy: Low
        $x_2_2 = {8b 55 08 8b 02 2b c1 8b 4d 08 89 01 5e 8b e5 5d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AR_2147758267_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AR!MTB"
        threat_id = "2147758267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {56 8b 45 0c 89 45 fc 8b 0d ?? ?? ?? ?? 89 4d 08 8b 55 08 8b 02 8b 4d fc 8d 94 01 c2 5a 00 00 8b 45 08 89 10}  //weight: 2, accuracy: Low
        $x_2_2 = {03 f0 8b 4d 08 8b 11 2b d6 8b 45 08 89 10 5e 8b e5 5d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AR_2147758267_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AR!MTB"
        threat_id = "2147758267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 8c 10 fd 8a 67 00 89 4d f8 8b 55 f8 81 ea fd 8a 67 00 89 55 f8 b8 3b bb fa ff 03 05 ?? ?? ?? ?? 8b 80 01 45 05 00 a3}  //weight: 1, accuracy: Low
        $x_1_2 = {03 4d f4 03 4d f4 8b 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 8a 04 06 88 04 0a 8b 0d ?? ?? ?? ?? 83 c1 01 89 0d ?? ?? ?? ?? eb 98}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AR_2147758267_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AR!MTB"
        threat_id = "2147758267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "buildable" ascii //weight: 1
        $x_1_2 = "euornithic" ascii //weight: 1
        $x_1_3 = "paranitrosophenol" ascii //weight: 1
        $x_1_4 = "photosynthetically" ascii //weight: 1
        $x_1_5 = "psephomancy" ascii //weight: 1
        $x_1_6 = "scyphostoma" ascii //weight: 1
        $x_1_7 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AR_2147758267_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AR!MTB"
        threat_id = "2147758267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 75 f4 03 c6 03 45 f4 8b 0d ?? ?? ?? ?? 03 4d f4 03 4d f4 03 4d f4 8b 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 8a 04 06 88 04 0a 8b 0d ?? ?? ?? ?? 83 c1 01 89 0d}  //weight: 2, accuracy: Low
        $x_1_2 = {8b d2 8b d2 a1 ?? ?? ?? ?? 8b d2 8b 0d ?? ?? ?? ?? 8b d2 a3 ?? ?? ?? ?? 8b c0 a1 ?? ?? ?? ?? a3}  //weight: 1, accuracy: Low
        $x_1_3 = {8b d2 8b 35 ?? ?? ?? ?? 33 f1 [0-8] c7 05 [0-8] 01 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_AR_2147758267_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AR!MTB"
        threat_id = "2147758267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 75 f4 03 c6 03 45 f4 8b 0d ?? ?? ?? ?? 03 4d f4 03 4d f4 03 4d f4 8b 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 8a 04 06 88 04 0a 8b 0d ?? ?? ?? ?? 83 c1 01 89 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d2 8b d2 8b d2 a1 ?? ?? ?? ?? 8b d2 8b 0d ?? ?? ?? ?? 8b d2 a3 ?? ?? ?? ?? 8b c0 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 31 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 01 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 1, accuracy: Low
        $x_1_3 = {8b d2 8b d2 8b 15 ?? ?? ?? ?? 31 0d [0-8] c7 05 [0-8] 8b 1d ?? ?? ?? ?? 01 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5b 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Qakbot_AR_2147758267_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AR!MTB"
        threat_id = "2147758267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 75 f4 03 c6 03 45 f4 8b 15 ?? ?? ?? ?? 03 55 f4 03 55 f4 03 55 f4 8b 0d ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 8a 04 06 88 04 11 8b 0d ?? ?? ?? ?? 83 c1 01 89 0d}  //weight: 2, accuracy: Low
        $x_1_2 = {8b d2 8b d2 a1 ?? ?? ?? ?? 8b d2 8b 0d ?? ?? ?? ?? 8b d2 a3 ?? ?? ?? ?? 8b c0 a1 ?? ?? ?? ?? a3}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 bc 01 00 00 b8 bc 01 00 00 31 0d [0-8] c7 05 [0-8] a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 1, accuracy: Low
        $x_1_4 = {b8 bc 01 00 00 b8 bc 01 00 00 31 0d ?? ?? ?? ?? eb [0-4] c7 05 [0-8] ff 35 ?? ?? ?? ?? 5a 01 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 1, accuracy: Low
        $x_1_5 = {b8 bc 01 00 00 31 0d ?? ?? ?? ?? eb 00 c7 05 [0-8] 8b 35 ?? ?? ?? ?? 01 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 1, accuracy: Low
        $x_1_6 = {b8 bc 01 00 00 b8 bc 01 00 00 31 0d ?? ?? ?? ?? eb 00 c7 05 ?? ?? ?? ?? 00 00 00 00 [0-70] a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 (5e|5d)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GC_2147760612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GC!MTB"
        threat_id = "2147760612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {fc f3 a4 8d 83 ?? ?? ?? ?? 50 8d 83 ?? ?? ?? ?? 50 ff 93 ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 56 c7 04 e4 ff ff 0f 00 59 8b 83 ?? ?? ?? ?? 83 bb ?? ?? ?? ?? 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GC_2147760612_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GC!MTB"
        threat_id = "2147760612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 d8 33 18 89 5d a0 8b 45 a0 03 45 9c 2b 45 9c 8b 55 d8 89 02 8b 45 d8 83 c0 04 03 45 9c 2b 45 9c 89 45 d8 8b 45 9c 2b 45 9c 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 a8 3b 45 cc 0f 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GC_2147760612_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GC!MTB"
        threat_id = "2147760612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 31 0d [0-4] c7 05 [0-4] 00 00 00 00 8b 1d [0-4] 01 1d [0-4] a1 [0-4] 8b 0d [0-4] 89 08 5b 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GC_2147760612_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GC!MTB"
        threat_id = "2147760612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 4d fc 31 c9 09 c1 89 8b ?? ?? ?? ?? 8b 4d fc 31 c9 8b 0c e4 83 c4 04 fc f3 a4 55 c7 04 e4 ff ff 0f 00 59 83 bb ?? ?? ?? ?? 00 75}  //weight: 10, accuracy: Low
        $x_10_2 = {89 0c e4 ff b3 ?? ?? ?? ?? 59 01 c1 89 8b ?? ?? ?? ?? 59 ff a3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GC_2147760612_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GC!MTB"
        threat_id = "2147760612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 02 8b 4d ?? 8d 94 01 ?? ?? ?? ?? 8b 45 ?? 89 10 8b 4d ?? 8b 11 81 ea ?? ?? ?? ?? 8b 45 ?? 89 10 8b e5}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d0 33 d1 8b c2 8b ff c7 05 [0-48] 8b ff 01 05 ?? ?? ?? ?? 8b ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GC_2147760612_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GC!MTB"
        threat_id = "2147760612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ba 01 00 00 00 6b c2 ?? 88 88 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ac cf 05 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 ?? 8b 0d ?? ?? ?? ?? 89 88 ?? ?? ?? ?? 6b 15 ?? ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 66 89 55 ?? e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GC_2147760612_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GC!MTB"
        threat_id = "2147760612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 da 0f b7 c2 02 d9 8a ca 0f b6 db 2b d8 83 eb ?? 2a cb 89 1d ?? ?? ?? ?? 80 e9 ?? 8b 44 24 ?? 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 89 30 8b 74 24 ?? 69 c2 ?? ?? ?? ?? 83 c6 04 0f b6 d1 89 74 24 ?? 66 2b d0 8b 44 24 10 66 03 15 ?? ?? ?? ?? 66 03 d0 83 6c 24 ?? 01 0f b7 d2 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GC_2147760612_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GC!MTB"
        threat_id = "2147760612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {be ac 00 00 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 94 01 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2d be ac 00 00 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 5d c3 3c 00 c7 05}  //weight: 10, accuracy: Low
        $x_10_2 = {03 f0 8b 45 08 03 30 8b 4d 08 89 31 [0-20] 8b 55 08 8b ?? 2b ?? 8b 55 08 89 ?? 5e 8b e5 5d c3}  //weight: 10, accuracy: Low
        $x_10_3 = {03 45 fc 88 1c 30 8b 4d f8 83 c1 01 89 4d f8 eb [0-15] 8b e5 5d c3}  //weight: 10, accuracy: Low
        $x_10_4 = {89 08 5f 5d c3 ff 00 33 [0-200] c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d}  //weight: 10, accuracy: Low
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_JG_2147760949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.JG!MTB"
        threat_id = "2147760949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5e 8b e5 5d c3 96 00 ba [0-4] 85 [0-2] 74 [0-2] a1 [0-4] 3b 05 [0-4] 72 02 eb 34 8b 0d [0-4] 03 4d [0-2] 8b 15 [0-4] 03 55 [0-2] a1 [0-4] 8b 35 [0-4] 8a 0c [0-2] 88 0c [0-2] 8b 15 [0-4] 83 c2 01 89 15 [0-4] eb}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 8b 45 [0-2] 89 45 [0-2] 8b 0d [0-4] 89 4d [0-2] 8b 55 [0-2] 8b 02 8b 4d [0-2] 8d 94 [0-5] 8b 45 [0-2] 89 10 68 [0-4] 6a 00 ff 15 [0-4] 05 [0-4] 8b 4d [0-2] 8b 11 2b d0 8b 45 [0-2] 89 10 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = {55 8b ec a1 [0-4] a3 [0-4] ff 35 [0-4] 6a 00 c7 04 [0-6] 81 2c [0-6] ff 35 [0-4] ff 35 [0-4] 6a ff ff 35 [0-4] 59 ff d1 a3 [0-4] 8b 0d [0-4] 89 0d [0-4] 8b 15 [0-4] 89 15 [0-4] a1 [0-4] 05 [0-4] a3 [0-4] a1 [0-4] 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_RQ_2147760963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RQ!MTB"
        threat_id = "2147760963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 8b 54 24 0c 8a c1 66 2b 17 f6 ea 66 89 54 24 0c 8a c8 0f b7 c2 99 80 c1 48}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_RQ_2147760963_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RQ!MTB"
        threat_id = "2147760963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "c:\\Finisheat\\alwaysMay\\Representelectric\\finalWheel\\PrintSeem\\sent.pdb" ascii //weight: 10
        $x_1_2 = "C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe   RemoteSigned" ascii //weight: 1
        $x_1_3 = "GetCurrentProcess" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "GetStartupInfoA" ascii //weight: 1
        $x_1_6 = " Receive-Job." ascii //weight: 1
        $x_1_7 = "GetCPInfo" ascii //weight: 1
        $x_1_8 = "GetTickCount" ascii //weight: 1
        $x_1_9 = "GetCurrentProcessId" ascii //weight: 1
        $x_1_10 = "1: Anonymous (" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_VD_2147762261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.VD!MTB"
        threat_id = "2147762261"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a1 e4 dc 6a 00 05 d0 3b 03 00 a3 c0 dc 6a 00 a1 74 df 6a 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b d8 8b 35 ?? ?? ?? ?? 33 f1 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qakbot_DHE_2147762832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DHE!MTB"
        threat_id = "2147762832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lafosopijib" ascii //weight: 1
        $x_1_2 = "cozocayixatu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MR_2147765414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MR!MTB"
        threat_id = "2147765414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f0 8b 55 08 8b 02 2b c6 8b 4d 08 89 01 8b 55 08 8b 02 83 c0 ?? 8b 4d 08 89 01 8b 55 08 8b 02 83 e8 ?? 8b 4d 08 89 01 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {89 08 5b 5d c3 2d 00 31 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 01 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GD_2147765648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GD!MTB"
        threat_id = "2147765648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {59 fc 51 8d 83 ?? ?? ?? ?? 50 8d 83 ?? ?? ?? ?? 50 ff 93 ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 59 f3 a4 8d 83 ?? ?? ?? ?? 50 ff 93 ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 57 c7 04 e4 ff ff 0f 00 59 51}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GD_2147765648_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GD!MTB"
        threat_id = "2147765648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b 15 [0-4] 33 d1 c7 05 [0-4] 00 00 00 00 8b da 01 1d [0-4] a1 [0-4] 8b 0d [0-4] 89 08 5b 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GD_2147765648_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GD!MTB"
        threat_id = "2147765648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 d1 8b 55 fc fc f3 a4 52 c7 04 e4 ff ff 0f 00 59 89 75 fc 33 75 fc 0b b3 ?? ?? ?? ?? 83 e0 00 09 f0 8b 75 fc 68 ?? ?? ?? ?? 8f 83 ?? ?? ?? ?? 21 8b ?? ?? ?? ?? 01 83 ?? ?? ?? ?? ff a3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GD_2147765648_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GD!MTB"
        threat_id = "2147765648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 17 80 c1 21 0f b6 c1 3b 05 ?? ?? ?? ?? 8b 44 24 ?? 81 c2 b0 70 08 01 8a cd 02 0d ?? ?? ?? ?? 89 17 83 c7 04 ff 4c 24 ?? 89 15 ?? ?? ?? ?? 8b 54 24 ?? 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GD_2147765648_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GD!MTB"
        threat_id = "2147765648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 d8 8b 45 d8 33 18 89 5d a0 8b 45 a0 03 45 9c 2b 45 9c 8b 55 d8 89 02}  //weight: 1, accuracy: High
        $x_1_2 = {03 d8 89 5d d8 8b 45 9c 2b 45 9c 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 a8 3b 45 cc 0f 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GD_2147765648_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GD!MTB"
        threat_id = "2147765648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {fe c6 0f b6 f6 8a 14 3e 02 c2 0f b6 c8 88 45 0b 8a 04 39 88 04 3e 88 14 39 8a 04 3e 8b 4d f8 02 c2 0f b6 c0 8a 04 38 30 04 0b 43 8a 45 0b 3b 5d fc 7c}  //weight: 4, accuracy: High
        $x_1_2 = {32 04 37 88 44 3b 04 47 3b 3b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GD_2147765648_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GD!MTB"
        threat_id = "2147765648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {51 83 e1 00 31 c1 83 a3 ?? ?? ?? ?? 00 09 8b ?? ?? ?? ?? 59 81 e1 00 00 00 00 8f 45 ?? 0b 4d ?? f3 a4 56 c7 04 e4 ff ff 0f 00 59 83 bb ?? ?? ?? ?? 00 75 ?? c7 45 ?? 00 00 00 00 ff 75 ?? 31 0c e4 50 8b 83 ?? ?? ?? ?? 87 04 e4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GD_2147765648_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GD!MTB"
        threat_id = "2147765648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 ce 8a f2 2b ce 2a f3 8b 74 24 [0-1] 81 c1 [0-4] 89 4c 24 [0-1] 80 c6 [0-1] 8a 54 24 [0-1] 89 0d [0-4] 80 c2 [0-1] 8b 0e 02 d3 81 c1 [0-4] 88 35 [0-4] 89 0e 83 c6 04 83 6c 24 [0-1] 01 89 74 24 [0-1] 8b 74 24 [0-1] 89 0d [0-4] 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GD_2147765648_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GD!MTB"
        threat_id = "2147765648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 85 6c ff ff ff ?? ?? ?? ?? c7 85 6c ff ff ff ?? ?? ?? ?? c7 85 6c ff ff ff ?? ?? ?? ?? c7 85 6c ff ff ff ?? ?? ?? ?? c7 85 6c ff ff ff ?? ?? ?? ?? c7 85 6c ff ff ff ?? ?? ?? ?? c7 85 6c ff ff ff ?? ?? ?? ?? c7 85 6c ff ff ff}  //weight: 10, accuracy: Low
        $x_10_2 = {03 f0 8b 45 08 03 30 8b 4d 08 89 31 [0-20] 8b 55 08 8b ?? 2b ?? 8b 55 08 89 ?? 5e 8b e5 5d c3}  //weight: 10, accuracy: Low
        $x_10_3 = "hZTDKTdJNS" wide //weight: 10
        $x_10_4 = "LoadCursorFromFileW" ascii //weight: 10
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GE_2147765649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GE!MTB"
        threat_id = "2147765649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {fc f3 a4 57 c7 04 e4 ff ff 0f 00 59 8b 83 ?? ?? ?? ?? 50 c7 04 e4 ?? ?? ?? ?? 8f 83 ?? ?? ?? ?? 21 8b ?? ?? ?? ?? 01 83 ?? ?? ?? ?? ff a3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GE_2147765649_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GE!MTB"
        threat_id = "2147765649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 31 0d [0-4] c7 05 [0-4] 00 00 00 00 8b 1d [0-4] 01 1d [0-4] a1 [0-4] 8b 0d [0-4] 89 08 5b 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GE_2147765649_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GE!MTB"
        threat_id = "2147765649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 c0 66 03 c6 66 89 44 24 ?? 0f b7 f0 8b 01 05 e8 66 03 01 89 01 8a cb a3 ?? ?? ?? ?? 80 e9 ?? 66 8b 44 24 ?? 02 c8 83 6c 24 ?? 01 88 4c 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GE_2147765649_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GE!MTB"
        threat_id = "2147765649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a de 0f b6 c6 80 eb [0-1] 2b 44 24 [0-1] 2d 4b c9 00 00 a3 [0-4] 8b 84 31 [0-4] 05 ?? ?? 06 01 88 1d [0-4] a3 [0-4] 89 84 31 [0-4] 83 c6 04 81 fe 7a 22 00 00 73}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GE_2147765649_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GE!MTB"
        threat_id = "2147765649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {fc f3 a4 52 c7 04 e4 ff ff 0f 00 59 83 bb ?? ?? ?? ?? 00 ?? ?? 51 51 56 8b b3 ?? ?? ?? ?? 89 74 e4 04 5e ff 93 ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 59 8b 83 ?? ?? ?? ?? 52 c7 04 e4 ?? ?? ?? ?? 83 bb ?? ?? ?? ?? 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GE_2147765649_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GE!MTB"
        threat_id = "2147765649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c9 83 c1 bb 8d 04 41 0f b7 c0 89 44 24 ?? 8b 02 05 a8 f8 02 01 89 02 83 c2 04 a3 ?? ?? ?? ?? 8b 44 24 ?? 83 c0 ?? 89 54 24 ?? 03 c1 83 6c 24 ?? 01 0f b6 c0 8d 04 c3 0f b7 f0 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GE_2147765649_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GE!MTB"
        threat_id = "2147765649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 e6 00 09 ce 59 89 7d ?? 83 e7 00 33 bb ?? ?? ?? ?? 83 e1 00 31 f9 8b 7d ?? fc f3 a4 55 c7 04 e4 ff ff 0f 00 59 56 2b 34 e4}  //weight: 10, accuracy: Low
        $x_10_2 = {6a 00 89 14 e4 ff b3 ?? ?? ?? ?? 5a 01 c2 89 93 ?? ?? ?? ?? 5a ff a3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GE_2147765649_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GE!MTB"
        threat_id = "2147765649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 a1 ?? ?? ?? ?? 33 18 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02}  //weight: 1, accuracy: Low
        $x_1_2 = {03 d8 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GE_2147765649_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GE!MTB"
        threat_id = "2147765649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 00 03 45 ?? 03 d8 [0-30] 2b d8 a1 [0-4] 89 18 8b 45 ?? 03 45 ?? 03 45 ?? 8b 15 [0-4] 31 02 a1 [0-4] 83 c0 04 a3 [0-4] 83 45 ?? 04 8b 45 ?? 3b 45}  //weight: 10, accuracy: Low
        $x_1_2 = {f3 ab 89 d1 83 e1 03 f3 aa 5f c3}  //weight: 1, accuracy: High
        $x_1_3 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GE_2147765649_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GE!MTB"
        threat_id = "2147765649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 45 fc 88 1c 30 8b 4d f8 83 c1 01 89 4d f8 eb [0-15] 8b e5 5d c3}  //weight: 10, accuracy: Low
        $x_10_2 = "RegOpenKeyA" ascii //weight: 10
        $x_10_3 = "ghrtye" ascii //weight: 10
        $x_10_4 = "KLIOY240LhK7vsoZCTJoUW4VOLYbKLxek4NpSzSTlPjz9R3w" ascii //weight: 10
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GF_2147765655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GF!MTB"
        threat_id = "2147765655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 18 8b 45 c4 03 45 a4 89 45 a0 e8 ?? ?? ?? ?? 8b 5d a0 2b d8 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GF_2147765655_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GF!MTB"
        threat_id = "2147765655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {3d c0 03 00 00 0f b7 c1 2b c2 83 c0 ?? 2b d8 83 df 00 8b 06 05 70 a0 07 01 89 06 83 c6 04 83 6c 24 ?? 01 a3 ?? ?? ?? ?? 8b 44 24 ?? 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GF_2147765655_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GF!MTB"
        threat_id = "2147765655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 d8 81 c1 a8 a1 02 01 89 0d ?? ?? ?? ?? 89 0a 0f b6 cb 66 2b 0d ?? ?? ?? ?? 66 2b ce 66 8b f1 8b ca 8b 15 ?? ?? ?? ?? 83 c1 04 ff 4c 24 ?? 66 89 35 ?? ?? ?? ?? 89 4c 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GF_2147765655_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GF!MTB"
        threat_id = "2147765655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 c9 f7 d9 2b c8 03 d9 8b 0d [0-4] 89 1d [0-4] 8b 84 11 [0-4] 05 0c f5 04 01 a3 [0-4] 89 84 11 [0-4] 83 c2 04 8b 35 [0-4] 8b 1d [0-4] 81 fa 83 11 00 00 73 ?? 8a 0d [0-4] eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GF_2147765655_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GF!MTB"
        threat_id = "2147765655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 dc 03 45 b0 03 45 ec [0-30] 31 ?? a1 [0-4] 83 c0 04 a3 [0-4] 83 45 ec 04 8b 45 ec 3b 45 e4 72}  //weight: 10, accuracy: Low
        $x_1_2 = {f3 ab 89 d1 83 e1 03 f3 aa 5f c3}  //weight: 1, accuracy: High
        $x_1_3 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GF_2147765655_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GF!MTB"
        threat_id = "2147765655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a ca 81 c6 88 3c 03 01 8b 54 24 [0-1] 2a ca 80 c1 [0-1] 89 35 [0-4] 89 b4 2b [0-4] 83 c5 04 8b 1d [0-4] 0f b6 c1 66 2b c3 89 6c 24 [0-1] 66 03 f8 66 89 7c 24 [0-1] 81 fd 4e 0a 00 00 73 [0-1] 8b 6c 24 [0-1] e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GF_2147765655_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GF!MTB"
        threat_id = "2147765655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 c2 50 01 07 01 8b 44 24 [0-1] 2b c3 89 15 [0-4] 2b 05 [0-4] 66 a3 [0-4] 89 94 2e [0-4] 83 c5 04 a1 [0-4] 0f b7 3d [0-4] 83 c0 [0-1] 8b 15 [0-4] 03 d7 03 d0 89 54 24 [0-1] 89 15 [0-4] 81 fd 4b 26 00 00 73}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GF_2147765655_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GF!MTB"
        threat_id = "2147765655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 c9 09 c1 89 8b [0-4] 8b 4d ?? 8f 45 ?? 8b 4d ?? f3 a4 b9 ff ff [0-2] 89 4d ?? 31 c9 33 8b [0-4] 89 c8 8b 4d ?? 56 c7 04 [0-5] 8f 83 [0-4] 21 8b [0-4] 57 8b bb [0-4] 50 8f 45 ?? 01 7d ?? ff 75 ?? 58 5f ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GF_2147765655_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GF!MTB"
        threat_id = "2147765655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 45 fc 88 1c 30 8b 4d f8 83 c1 01 89 4d f8 eb [0-15] 8b e5 5d c3}  //weight: 10, accuracy: Low
        $x_10_2 = {be ac 00 00 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 94 01 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2d be ac 00 00 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 5d c3 3c 00 c7 05}  //weight: 10, accuracy: Low
        $x_10_3 = "RegOpenKeyA" ascii //weight: 10
        $x_10_4 = "KLIOY240LhK7vsoZCTJoUW4VOLYbKLxek4NpSzSTlPjz9R3w" ascii //weight: 10
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GH_2147765760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GH!MTB"
        threat_id = "2147765760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 e6 00 09 d6 8b 55 ?? 89 75 ?? 2b 75 ?? 0b b3 ?? ?? ?? ?? 83 e1 00 31 f1 8b 75 ?? fc f3 a4 2d 00 89 55 [0-4] 33 93}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GH_2147765760_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GH!MTB"
        threat_id = "2147765760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 02 8b 45 d8 03 45 b0 03 45 e8 89 45 b4 6a 00 e8 ?? ?? ?? ?? 8b 5d b4 2b d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 ec 31 18 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GH_2147765760_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GH!MTB"
        threat_id = "2147765760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 c1 3c 73 0d 01 89 0d [0-4] 89 54 24 [0-1] 89 15 [0-4] 89 0b 83 c3 04 0f b6 c8 66 83 c1 [0-1] 89 5c 24 [0-1] 66 03 4c 24 [0-1] 83 6c 24 [0-1] 01 66 8b f9 89 7c 24 [0-1] 66 89 3d [0-4] 0f b7 d9 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GH_2147765760_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GH!MTB"
        threat_id = "2147765760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 1c e4 29 db 09 c3 89 df 5b 89 55 f8 83 e2 00 31 fa 83 a3 ?? ?? ?? ?? 00 31 93 ?? ?? ?? ?? 8b 55 f8 83 fb 00}  //weight: 10, accuracy: Low
        $x_10_2 = {89 55 f8 83 e2 00 33 93 ?? ?? ?? ?? 83 e6 00 09 d6 8b 55 f8 6a 00 89 3c e4 31 ff 0b bb ?? ?? ?? ?? 89 f9 5f fc f3 a4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GH_2147765760_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GH!MTB"
        threat_id = "2147765760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {fc f3 a4 50 c7 04 e4 ff ff 0f 00 59 89 55 ?? 2b 55 ?? 33 93 [0-4] 83 e0 00 31 d0 8b 55 ?? 53 c7 04 e4 [0-4] 8f 83 [0-4] 21 8b [0-4] 89 7d ?? 89 c7 03 bb [0-4] 57 8b 7d ?? 8f 83 [0-4] ff a3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GH_2147765760_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GH!MTB"
        threat_id = "2147765760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 83 e6 00 09 c6 83 e7 00 31 f7 5e 52 33 14 ?? 31 fa 83 a3 ?? ?? ?? ?? 00 31 93 ?? ?? ?? ?? 5a 83 fb 00 ?? ?? 89 7d f8 89 df 03 bb ?? ?? ?? ?? 57}  //weight: 10, accuracy: Low
        $x_10_2 = {5e 89 55 f8 83 e2 00 0b 93 ?? ?? ?? ?? 83 e1 00 31 d1 8b 55 f8 fc f3 a4 50}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GH_2147765760_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GH!MTB"
        threat_id = "2147765760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d8 8b 45 ?? 03 45 ?? 03 45 ?? 03 d8 [0-8] 2b d8 8b 45 ?? 31 [0-255] 83 45 ?? 04 8b 45 ?? 3b 45 ?? 0f 82}  //weight: 10, accuracy: Low
        $x_1_2 = {f3 ab 89 d1 83 e1 03 f3 aa 5f c3}  //weight: 1, accuracy: High
        $x_1_3 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GH_2147765760_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GH!MTB"
        threat_id = "2147765760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 53 57 a1 [0-4] a3 [0-4] 8b 0d [0-4] 8b 11 89 15 [0-4] 8b 15 [0-4] a1 [0-4] 50 8f 05 [0-4] 8b 3d [0-4] 89 15 [0-4] 8b c7 eb 00 eb 00 eb 00 eb 00 eb 00 eb 00 bb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b c8 8b d1 89 15 [0-4] a1 [0-4] 8b 0d [0-4] 89 08 5f 5b 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GH_2147765760_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GH!MTB"
        threat_id = "2147765760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 c9 2b ca 03 c1 8a c8 2a ca 80 e9 ?? 88 0d ?? ?? ?? ?? 83 ee ?? 83 fe ?? ?? ?? 5f 89 35 ?? ?? ?? ?? 8b c3 5e 5b 59 c3}  //weight: 10, accuracy: Low
        $x_10_2 = {55 8b ec 6a ff 68 ?? ?? ?? ?? 64 a1 00 00 00 00 50 81 ec ?? ?? ?? ?? 53 56 57 a1 ?? ?? ?? ?? 33 c5 50 8d 45 f4 64 a3 00 00 00 00 89 65 f0 68 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GH_2147765760_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GH!MTB"
        threat_id = "2147765760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b7 55 f4 2b ca 89 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 05 70 83 07 01 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 8b 15 ?? ?? ?? ?? 89 91 ?? ?? ?? ?? a1 ?? ?? ?? ?? 6b c0 ?? 03 05 ?? ?? ?? ?? 66 89 45 ?? e9}  //weight: 10, accuracy: Low
        $x_10_2 = {0f b6 c8 81 c2 80 f6 ff ff 03 ca 8b 54 24 ?? 89 0d ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 8d 8e ?? ?? ?? ?? 89 4d 00 83 c5 04 89 0d ?? ?? ?? ?? b1 a7 2a ca 2a 0d ?? ?? ?? ?? 02 c1 83 6c 24 ?? 01 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qakbot_GH_2147765760_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GH!MTB"
        threat_id = "2147765760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 f0 8b 45 08 03 30 8b 4d 08 89 31 8b 55 08 8b 02 2d ?? ?? 00 00 8b 4d 08 89 01 5e 8b e5 5d c3}  //weight: 10, accuracy: Low
        $x_10_2 = {03 45 fc 88 1c 30 8b 55 f8 83 c2 01 89 55 f8 eb ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 5e 5b 8b e5 5d c3}  //weight: 10, accuracy: Low
        $x_10_3 = {89 11 5d c3 28 00 31 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15}  //weight: 10, accuracy: Low
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GI_2147765947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GI!MTB"
        threat_id = "2147765947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 33 ?? 03 ?? [0-30] 89 ?? 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GI_2147765947_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GI!MTB"
        threat_id = "2147765947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 33 ?? 03 ?? [0-40] 89 ?? 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GI_2147765947_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GI!MTB"
        threat_id = "2147765947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f3 a4 52 c7 04 e4 ?? ?? ?? ?? 59 8b 83 ?? ?? ?? ?? 56 c7 04 ?? ?? ?? ?? ?? 8f 83 ?? ?? ?? ?? 21 8b ?? ?? ?? ?? 6a 00 01 3c ?? 50 5f 03 bb ?? ?? ?? ?? 89 f8 5f ff e0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GI_2147765947_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GI!MTB"
        threat_id = "2147765947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 [0-40] 31 0d [0-8] c7 05 [0-4] 00 00 00 00 8b 1d [0-4] 01 1d [0-4] a1 [0-4] 8b 0d [0-4] 89 08 5b 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GI_2147765947_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GI!MTB"
        threat_id = "2147765947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 33 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 a1 ?? ?? ?? ?? 83 c0 04 a3 ?? ?? ?? ?? 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GI_2147765947_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GI!MTB"
        threat_id = "2147765947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d8 8b 45 ?? 03 45 ?? 03 45 ?? 03 d8 [0-8] 2b d8 8b 45 ?? 31 18}  //weight: 10, accuracy: Low
        $x_1_2 = {f3 ab 89 d1 83 e1 03 f3 aa 5f c3}  //weight: 1, accuracy: High
        $x_1_3 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GI_2147765947_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GI!MTB"
        threat_id = "2147765947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 00 88 86 0c 00 8b c6 05}  //weight: 1, accuracy: Low
        $x_10_2 = {0f b6 c3 b2 ?? f6 ea 02 c1 a2 ?? ?? ?? ?? b8 ?? ?? ?? ?? 66 39 05 ?? ?? ?? ?? 75 ?? 0f b6 c3 a3 ?? ?? ?? ?? 8d 86 ?? ?? ?? ?? 03 c8 8b 44 24 ?? 83 d5 00 83 44 24 ?? 04 81 c7 ?? ?? ?? ?? ff 4c 24 ?? 89 3d ?? ?? ?? ?? 89 38 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GI_2147765947_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GI!MTB"
        threat_id = "2147765947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8b d8 8b 45 [0-3] 03 45 [0-3] 03 d8 [0-8] 2b d8 8b 45 [0-30] 31}  //weight: 20, accuracy: Low
        $x_5_2 = {f3 ab 89 d1 83 e1 03 f3 aa 5f c3}  //weight: 5, accuracy: High
        $x_5_3 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GI_2147765947_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GI!MTB"
        threat_id = "2147765947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 18 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 5a 00 03 d8 [0-7] 2b d8 [0-7] 03 d8 [0-7] 2b d8}  //weight: 10, accuracy: Low
        $x_5_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GI_2147765947_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GI!MTB"
        threat_id = "2147765947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b7 45 f8 99 03 c8 88 4d ff 8b 15 ?? ?? ?? ?? 81 c2 d4 b4 08 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 ?? 8b 0d ?? ?? ?? ?? 89 88 ?? ?? ?? ?? 0f b7 55 ?? a1 ?? ?? ?? ?? 8d 8c 10 ?? ?? ?? ?? 66 89 4d ?? e9}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 02 05 58 f3 0b 01 89 02 83 c2 04 a3 ?? ?? ?? ?? 0f b7 c3 2b c8 89 54 24 18 8b 15 ?? ?? ?? ?? 8d 04 cd 00 00 00 00 2b c1 2b 05 ?? ?? ?? ?? 03 44 24 ?? 01 44 24 ?? 83 6c 24 ?? 01 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qakbot_GJ_2147765948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GJ!MTB"
        threat_id = "2147765948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 12 8b 0d ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 33 d1 03 c2 8b 15 ?? ?? ?? ?? 89 02 83 05 ?? ?? ?? ?? ?? 83 05 ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GJ_2147765948_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GJ!MTB"
        threat_id = "2147765948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e8 8b 55 ec 01 02 8b 45 d8 03 45 b0 03 45 e8 89 45 b4 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_2 = {2b d8 8b 45 ec 31 18 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GJ_2147765948_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GJ!MTB"
        threat_id = "2147765948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 e6 00 31 fe 8b 7d fc 55 33 2c e4 0b ab [0-4] 83 e1 00 31 e9 5d fc f3 a4 56 c7 04 e4 ff ff 0f 00 59 ff b3 [0-4] 8f 45 fc ff 75 fc 58 53 81 04 e4 [0-4] 29 1c e4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GJ_2147765948_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GJ!MTB"
        threat_id = "2147765948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec fc f3 a4 [0-30] 29 c9 09 c1 89 8b [0-4] 59 52 c7 04 [0-6] 59 55 83 e5 00 0b ab [0-4] 83 e0 00 09 e8 5d 68 [0-4] 8f 83 [0-4] 21 8b [0-4] 89 4d [0-2] 8b 8b [0-4] 01 c1 51 8b 4d [0-2] 58 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GJ_2147765948_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GJ!MTB"
        threat_id = "2147765948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 c3 3b 05 [0-4] a1 [0-4] 80 c3 ?? 02 db 81 c6 [0-4] 2a da 89 35 [0-4] 02 1d [0-4] 89 b4 28 [0-4] 83 c5 04 81 fd 4e 07 00 00 73 1d 8b 35 [0-4] 8b 0d [0-4] 8b 3d [0-4] 8b 15 [0-4] e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GJ_2147765948_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GJ!MTB"
        threat_id = "2147765948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 d8 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 [0-7] 8b d8 8b 45 ?? 83 c0 ?? 03 d8 [0-80] 2b d8 [0-4] 8b 45 ?? 3b 45 ?? 0f 82}  //weight: 10, accuracy: Low
        $x_5_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GJ_2147765948_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GJ!MTB"
        threat_id = "2147765948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d8 8b 45 cc 03 45 ac 2d f2 05 00 00 03 45 a0 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d8 31 18}  //weight: 10, accuracy: Low
        $x_5_2 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 14 00 99 52 50}  //weight: 5, accuracy: Low
        $x_5_3 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GJ_2147765948_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GJ!MTB"
        threat_id = "2147765948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2d f2 05 00 00 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02 2d 00 a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 01 02 a1 ?? ?? ?? ?? 03 05}  //weight: 10, accuracy: Low
        $x_10_2 = {2b d8 01 1d ?? ?? ?? ?? 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 99 [0-2] a1 ?? ?? ?? ?? 33 d2 3b 54 24}  //weight: 10, accuracy: Low
        $x_5_3 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GJ_2147765948_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GJ!MTB"
        threat_id = "2147765948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8b 00 03 05 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 89 18 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 83 e8 5a 03 05 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18}  //weight: 20, accuracy: Low
        $x_5_2 = {f3 ab 89 d1 83 e1 03 f3 aa 5f c3}  //weight: 5, accuracy: High
        $x_5_3 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GJ_2147765948_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GJ!MTB"
        threat_id = "2147765948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b d8 8b 45 ?? 89 18 [0-7] 8b d8 8b 45 ?? 03 45 ?? 2d f2 05 00 00 03 45 ?? 03 d8 [0-7] 2b d8 8b 45 ?? 31}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 00 03 05 ?? ?? ?? ?? 03 d8 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 89 18 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 d8 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 e8 ?? ?? ?? ?? 8b d8 83 c3 04}  //weight: 10, accuracy: Low
        $x_5_3 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_MS_2147765965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MS!MTB"
        threat_id = "2147765965"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 4d ?? 81 c1 ?? ?? ?? ?? 89 4d ?? 8b 55 ?? 6b d2 ?? 89 55 ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 33 c0 8b 4c 05 ?? 89 0d ?? ?? ?? ?? 89 2d ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GK_2147766014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GK!MTB"
        threat_id = "2147766014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 d8 03 45 b0 03 45 e8 89 45 b4 6a 00 e8 ?? ?? ?? ?? 8b 5d b4 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 03 d8 43 8b 45 ec 31 18 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GK_2147766014_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GK!MTB"
        threat_id = "2147766014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fc f3 a4 57 c7 04 e4 [0-4] 59 89 7d ?? 33 7d ?? 0b bb [0-4] 83 e0 00 31 f8 8b 7d ?? 68 [0-4] 8f 83 [0-4] 21 8b [0-4] 89 4d ?? 8b 8b [0-4] 01 c1 51 8b 4d ?? 58 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GK_2147766014_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GK!MTB"
        threat_id = "2147766014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 10 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 a1 ?? ?? ?? ?? 83 c0 04 a3 ?? ?? ?? ?? 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82 0d 00 8b 15 ?? ?? ?? ?? 2b d0 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GK_2147766014_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GK!MTB"
        threat_id = "2147766014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 4f 05 ?? ?? ?? ?? 0f af f7 8a 00 88 81 ?? ?? ?? ?? 41 69 f6}  //weight: 1, accuracy: Low
        $x_10_2 = {0f b7 c2 03 c0 2b f8 8b 03 2b 7c 24 ?? 05 ?? ?? ?? ?? 2b f9 89 03 a3 ?? ?? ?? ?? 83 c7 f0 8b c7 2b 44 24 ?? 2b c2 83 6c 24 ?? 01 0f b7 d8 a1 ?? ?? ?? ?? 89 5c 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GK_2147766014_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GK!MTB"
        threat_id = "2147766014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 10, accuracy: High
        $x_10_2 = {03 d8 01 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? eb 78 00 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 73 ?? 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? e8}  //weight: 10, accuracy: Low
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GK_2147766014_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GK!MTB"
        threat_id = "2147766014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 10, accuracy: High
        $x_10_2 = {73 45 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? eb ae 5a 00 a1 ?? ?? ?? ?? 3b 05}  //weight: 10, accuracy: Low
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GK_2147766014_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GK!MTB"
        threat_id = "2147766014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {03 d8 01 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? eb 96 00 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 73 ?? 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? e8}  //weight: 20, accuracy: Low
        $x_5_2 = {f3 ab 89 d1 83 e1 03 f3 aa 5f c3}  //weight: 5, accuracy: High
        $x_5_3 = {f3 a5 89 c1 83 e1 03 f3 a4 5f 5e c3}  //weight: 5, accuracy: High
        $x_5_4 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GL_2147766015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GL!MTB"
        threat_id = "2147766015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 [0-25] 33 d9 [0-2] c7 05 [0-4] 00 00 00 00 [0-6] 01 1d [0-4] a1 [0-4] 8b 0d [0-4] 89 08 5b 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GL_2147766015_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GL!MTB"
        threat_id = "2147766015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 4d 08 8d 4c 02 d0 ba ?? ?? ?? ?? 2b d0 03 ca 83 c4 0c 8b f0 c6 05 ?? ?? ?? ?? fc 89 0d ?? ?? ?? ?? 8b 7d 08 05 ?? ?? ?? ?? ff d7 46 00 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GL_2147766015_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GL!MTB"
        threat_id = "2147766015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 fc 01 10 [0-24] ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 8b 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 55 fc 33 c2 03 d8}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GL_2147766015_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GL!MTB"
        threat_id = "2147766015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 18 8b 45 c4 03 45 a4 89 45 a0 6a 00 e8 ?? ?? ?? ?? 8b 5d a0 2b d8 4b 6a 00 [0-10] e8 ?? ?? ?? ?? 2b d8 4b 8b 45 d8 33 18 89 5d a0 6a 00 e8 ?? ?? ?? ?? 8b d8 03 5d a0 6a 00 e8 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 89 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GL_2147766015_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GL!MTB"
        threat_id = "2147766015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 f0 2b f3 b3 ?? f6 eb 03 f7 2a d0 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b 75 00 88 15 ?? ?? ?? ?? 75 [0-10] 66 0f b6 44 24 ?? 8b 1d ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 66 2b c3 89 75 00 66 83 c0 ?? 83 c5 04 ff 4c 24 ?? 89 35 ?? ?? ?? ?? 0f b7 d0 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GL_2147766015_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GL!MTB"
        threat_id = "2147766015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 fc 01 10 [0-12] 8b d8 a1 ?? ?? ?? ?? 05 ?? ?? ?? ?? 03 45 fc 03 d8 a1 ?? ?? ?? ?? 33 18}  //weight: 10, accuracy: Low
        $x_10_2 = {03 d8 01 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? e9}  //weight: 10, accuracy: Low
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GL_2147766015_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GL!MTB"
        threat_id = "2147766015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 cc 03 45 ac 2d f2 05 00 00 [0-12] 8b ?? d8 31 [0-90] 33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 18 00 99 52 50}  //weight: 10, accuracy: Low
        $x_5_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GL_2147766015_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GL!MTB"
        threat_id = "2147766015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b d8 89 5d ?? 8b 45 ?? 03 45 ?? 8b 55 ?? 31 02 [0-7] 8b d8 8b 45 e8 83 c0 04 03 d8 [0-80] 8b 45 ?? 3b 45 ?? 0f 82}  //weight: 10, accuracy: Low
        $x_5_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GL_2147766015_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GL!MTB"
        threat_id = "2147766015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b ec 83 c4 e4 8d 45 fc 50 68 40 00 00 00 68 71 0c 00 00 68 61 40 0a 10 68 ff ff ff ff ff 15 ?? ?? ?? ?? 8b c5 8b e5 5d c3}  //weight: 10, accuracy: Low
        $x_5_2 = {81 e8 04 7a cc 8e 33 05 ?? ?? ?? ?? 2b c6 83 f0 6f 81 c0 7c f7 41 71 89 45 ?? e8 ?? ?? ?? ?? e8}  //weight: 5, accuracy: Low
        $x_3_3 = {34 1a 68 12 dc 09 10 c3}  //weight: 3, accuracy: High
        $x_2_4 = {c0 c8 06 68 e1 0a 0a 10 c3}  //weight: 2, accuracy: High
        $x_1_5 = "VirtualProtectEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GL_2147766015_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GL!MTB"
        threat_id = "2147766015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 fc 01 10 a1 ?? ?? ?? ?? 05 ?? ?? ?? ?? 03 45 fc 8b 15 ?? ?? ?? ?? 31 02 83 45 fc 04 83 05 ?? ?? ?? ?? 04}  //weight: 10, accuracy: Low
        $x_4_2 = {03 d8 01 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? e9}  //weight: 4, accuracy: Low
        $x_4_3 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 4, accuracy: High
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GN_2147766447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GN!MTB"
        threat_id = "2147766447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 33 [0-200] 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GN_2147766447_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GN!MTB"
        threat_id = "2147766447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 02 01 01 31 33 ?? c7 05 ?? ?? ?? ?? 00 00 00 00 01 [0-5] a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GN_2147766447_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GN!MTB"
        threat_id = "2147766447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 4b a1 ?? ?? ?? ?? 33 18 89 1d [0-50] 03 d8 a1 ?? ?? ?? ?? 89 18 [0-10] 8b d8 a1 ?? ?? ?? ?? 83 c0 04 03 d8 [0-10] 03 d8 89 1d ?? ?? ?? ?? 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GN_2147766447_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GN!MTB"
        threat_id = "2147766447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 31 0d [0-4] eb 00 c7 05 [0-90] 01 [0-5] a1 [0-4] 8b 0d [0-4] 89 08 5e 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GN_2147766447_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GN!MTB"
        threat_id = "2147766447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b d1 89 55 ?? 0f b6 05 [0-4] 03 45 ?? 89 45 ?? 0f b6 0d [0-4] 8b 55 ?? 2b d1 89 55 ?? 0f b6 05 [0-4] 03 45 ?? 89 45 ?? 0f b6 0d [0-4] 33 4d ?? 89 4d ?? 8b 15 [0-4] 03 55 ?? 8a 45 ?? 88 02 e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GN_2147766447_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GN!MTB"
        threat_id = "2147766447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a ff ff 35 [0-4] 59 ff d1 28 00 8b 15 [0-4] 89 15 [0-4] ff 75 [0-1] b9 [0-4] 51 ff 75 [0-1] ff 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 33 c0 ff 00 04 01 01 01 01 31 32 30 33 [0-200] a1 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 01 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GN_2147766447_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GN!MTB"
        threat_id = "2147766447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 71 00 00 00 ff ?? ?? ?? ?? ?? b8 dd 09 00 00 ff ?? ?? ?? ?? ?? b8 16 02 00 00 ff ?? ?? ?? ?? ?? b8 ?? 02 00 00 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? b8 01 00 00 00 50 ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GN_2147766447_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GN!MTB"
        threat_id = "2147766447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 71 00 00 00 ff [0-5] b8 dd 09 00 00 ff [0-5] b8 16 02 00 00 ff [0-5] b8 ?? 02 00 00 ff [0-5] ff [0-5] b8 01 00 00 00 50 ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GN_2147766447_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GN!MTB"
        threat_id = "2147766447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fc f3 a4 83 bb [0-4] 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {50 5d 03 ab [0-4] 89 e8 5d ff 75 [0-2] 89 04 [0-2] 8d 83 [0-4] 51 29 0c [0-2] 01 04 [0-2] 8d 83 [0-4] ff 75 [0-2] 89 04 [0-2] ff 93 [0-4] 50 8f 45 [0-2] ff 75 [0-2] 8f 83 [0-4] 8f 45 [0-2] 8b 45 [0-2] ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GN_2147766447_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GN!MTB"
        threat_id = "2147766447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 10 8b 45 ?? 03 45 ?? 03 45 ?? 89 45 ?? [0-7] 8b d8 03 5d [0-8] 2b d8 8b 45 ?? 33 18 89 5d}  //weight: 10, accuracy: Low
        $x_5_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GN_2147766447_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GN!MTB"
        threat_id = "2147766447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a ff ff 35 [0-4] 59 ff d1 28 00 8b 15 [0-4] 89 15 [0-4] ff 75 [0-1] b9 [0-4] 51 ff 75 [0-1] ff 75}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 f0 e9 00 00 b8 f0 e9 00 00 b8 f0 e9 00 00 b8 f0 e9 00 00 31 0d [0-200] a1 [0-4] c7 05 [0-4] 00 00 00 00 01 05 [0-4] 8b ff 8b 0d [0-4] 8b 15 [0-4] 89 11 33 c0 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GN_2147766447_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GN!MTB"
        threat_id = "2147766447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2d 00 10 00 00 89 45 ec 83 45 ec 04 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 71 00 00 00 ff 75 ?? b8 ?? ?? ?? ?? ff 75 ?? b8 ?? ?? ?? ?? ff 75 ?? b8 ?? ?? ?? ?? ff 75 ?? ff 35 ?? ?? ?? ?? b8 01 00 00 00 50 ff 65 ec}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GN_2147766447_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GN!MTB"
        threat_id = "2147766447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d8 8b 45 ?? 03 45 ?? 03 45 ?? 03 d8 [0-10] 2b d8 [0-10] 03 d8 [0-10] 2b d8 8b 45 ?? 31 18 [0-10] 8b ?? 83 c3 04 [0-60] 2b d8 [0-4] 8b 45 ?? 3b 45 ?? 0f 82}  //weight: 10, accuracy: Low
        $x_5_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GN_2147766447_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GN!MTB"
        threat_id = "2147766447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 af 00 01 02 a1 ?? ?? ?? ?? 2d 32 02 00 00 03 05 ?? ?? ?? ?? a3 [0-60] 31 02}  //weight: 10, accuracy: Low
        $x_5_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_5_3 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 [0-5] 03 [0-5] 8b [0-5] e8}  //weight: 5, accuracy: Low
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GN_2147766447_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GN!MTB"
        threat_id = "2147766447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 d8 03 45 ?? 03 45 ?? 8b 55 ?? 31 [0-8] 8b d8 8b 45 ?? 83 c0 ?? 03 d8 [0-7] 2b d8}  //weight: 10, accuracy: Low
        $x_5_2 = {8b d8 8b 45 ?? 83 c0 ?? 03 d8 [0-7] 2b d8 89 5d ?? 8b 45 ?? 3b 45}  //weight: 5, accuracy: Low
        $x_5_3 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GN_2147766447_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GN!MTB"
        threat_id = "2147766447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58}  //weight: 10, accuracy: Low
        $x_10_2 = {2d 00 10 00 00 a3 ?? ?? ?? ?? 83 05 ?? ?? ?? ?? 04 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 6a 01 ff}  //weight: 10, accuracy: Low
        $x_5_3 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 [0-5] 03 [0-5] 8b [0-5] e8}  //weight: 5, accuracy: Low
        $x_5_4 = {99 03 04 24 13 54 24 04 83 c4 08 [0-30] 8b d0 8b [0-6] e8}  //weight: 5, accuracy: Low
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GN_2147766447_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GN!MTB"
        threat_id = "2147766447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 51 8b 15 [0-4] 52 ff 15 [0-4] a1 [0-4] a3 [0-4] 68 [0-4] e8 [0-4] 83 c4 04 8b 0d [0-4] 89 0d [0-4] 8b 0d [0-4] 81 e9 [0-4] 51 c7 05 [0-8] ff 05 [0-4] ff 35 [0-4] ff 35 [0-4] ff 35 [0-4] a1 [0-4] ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 00 00 8b 0d [0-4] 03 0d [0-4] 0f be 11 a1 [0-4] 03 05 [0-4] 0f be 08 03 ca 8b 15 [0-4] 03 15 [0-4] 88 0a a1 [0-4] 83 c0 01 a3 [0-4] eb [0-1] 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = {89 08 5f 5d c3 23 00 04 01 01 01 01 31 32 30 33 [0-5] 8b c8 8b d1 89 15 [0-4] a1 [0-4] 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GN_2147766447_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GN!MTB"
        threat_id = "2147766447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 7d 00 01 02 a1 ?? ?? ?? ?? 2d 32 02 00 00 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02}  //weight: 10, accuracy: Low
        $x_10_2 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 af 00 01 02 a1 ?? ?? ?? ?? 2d 32 02 00 00 03 05 ?? ?? ?? ?? a3 [0-50] 31 18}  //weight: 10, accuracy: Low
        $x_5_3 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_5_4 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 [0-5] 03 [0-5] 8b [0-5] e8}  //weight: 5, accuracy: Low
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GN_2147766447_18
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GN!MTB"
        threat_id = "2147766447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 1c 64 a1 18 00 00 00 3e 8b [0-1] 30 3e 8b [0-1] 0c 89 [0-12] 8b 48 0c [0-25] b8 01 00 00 00 85 c0 0f 84 [0-4] 83 [0-5] 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d fc 51 8b 15 [0-4] 52 ff 15 [0-4] a1 [0-4] a3 [0-4] 68 [0-4] e8 [0-4] 83 c4 04 8b 0d [0-4] 89 0d [0-4] 8b 0d [0-4] 81 e9 [0-4] 51 c7 05 [0-8] ff 05 [0-4] ff 35 [0-4] ff 35 [0-4] ff 35 [0-4] a1 [0-4] ff d0}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 00 00 8b 0d [0-4] 03 0d [0-4] 0f be 11 a1 [0-4] 03 05 [0-4] 0f be 08 03 ca 8b 15 [0-4] 03 15 [0-4] 88 0a a1 [0-4] 83 c0 01 a3 [0-4] eb [0-1] 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_4 = {89 08 5f 5b 5d c3 23 00 04 01 01 01 01 31 32 30 33 [0-5] 8b c8 8b d1 89 15 [0-4] a1 [0-4] 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Qakbot_GN_2147766447_19
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GN!MTB"
        threat_id = "2147766447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {99 03 04 24 13 54 24 04 83 c4 ?? 8b d0 8b 45 ?? 03 45 ?? 8b 4d ?? e8}  //weight: 5, accuracy: Low
        $x_10_2 = {2b d8 89 5d ?? 8b 45 ?? 03 45 ?? 8b 55 ?? 04 01 01 01 01 30 32 31 33 [0-15] 83 45 ?? 04 83 45 ?? 04 8b 45}  //weight: 10, accuracy: Low
        $x_10_3 = {2b d8 8b 45 ?? 04 01 01 01 01 30 32 31 33 [0-1] 89 5d ?? 8b 45 ?? 8b 55 ?? 89 02 83 45 ?? 04 83 45 ?? 04 8b 45}  //weight: 10, accuracy: Low
        $x_10_4 = {2b d8 89 5d ?? 8b 45 [0-4] 02 01 01 31 33 [0-15] 8b 45 ?? 8b 55 ?? 89 02 83 45 ?? 04 83 45 ?? 04 8b 45}  //weight: 10, accuracy: Low
        $x_5_5 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_1_6 = "VirtualAlloc" ascii //weight: 1
        $x_1_7 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GN_2147766447_20
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GN!MTB"
        threat_id = "2147766447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec [0-2] 64 a1 18 00 00 00 3e 8b [0-2] 30 3e 8b [0-2] 0c 89 0d [0-4] a1 [0-4] 8b 48 0c 89 0d [0-4] 8b 15 [0-4] 89 15 [0-4] b8 01 00 00 00 85 c0 0f 84 [0-4] 83 3d [0-4] 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec eb 00 a1 [0-4] a3 [0-4] ff 35 [0-4] 6a 00 c7 04 [0-6] 81 2c [0-6] ff 35 [0-4] ff 35 [0-4] ff 35 [0-4] 59 ff d1}  //weight: 1, accuracy: Low
        $x_1_3 = {03 c6 03 45 [0-2] 8b 15 [0-4] 03 55 [0-2] 03 55 [0-2] 03 55 [0-2] 8b 0d [0-4] 8b 35 [0-4] 8a 04 [0-2] 88 04 [0-2] 8b 0d [0-4] 83 c1 01 89 0d [0-4] eb [0-2] 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_4 = {b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 04 01 01 01 01 31 32 30 33 [0-6] eb 00 c7 05 [0-4] 00 00 00 00 [0-90] 01 [0-5] a1 [0-4] 8b 0d [0-4] 89 08 5e 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Qakbot_CK_2147767465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.CK!MTB"
        threat_id = "2147767465"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 0c 10 8d 1c 0f 83 e3 ?? 8a 9b ?? ?? ?? 00 32 1c 16 42 88 19 3b 55 fc 72 e6}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d1 83 e2 ?? 8a 92 ?? ?? ?? 00 32 14 08 74 07 41 3b ce 72 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_CK_2147767465_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.CK!MTB"
        threat_id = "2147767465"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "I_gmp_binvert_limb_table" ascii //weight: 1
        $x_1_2 = "I_gmp_default_fp_limb_precision" ascii //weight: 1
        $x_1_3 = "I_gmp_jacobi_table" ascii //weight: 1
        $x_1_4 = "I_gmp_mt_recalc_buffer" ascii //weight: 1
        $x_1_5 = "I_gmpn_nussbaumer_mul" ascii //weight: 1
        $x_1_6 = "I_gmpn_rshift_k6_k62mmx" ascii //weight: 1
        $x_1_7 = "I_gmpn_strongfibo" ascii //weight: 1
        $x_1_8 = "I_gmpn_submul_1c_pentium4_sse2" ascii //weight: 1
        $x_1_9 = "I_gmpn_toom_couple_handling" ascii //weight: 1
        $x_1_10 = "I_gmpz_millerrabin" ascii //weight: 1
        $x_1_11 = "I_gmpz_tdiv_r_2exp" ascii //weight: 1
        $x_1_12 = "I_gmpz_ui_kronecker" ascii //weight: 1
        $x_1_13 = "Nikn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GO_2147767650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GO!MTB"
        threat_id = "2147767650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 33 [0-255] 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GO_2147767650_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GO!MTB"
        threat_id = "2147767650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 33 [0-100] 89 18 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GO_2147767650_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GO!MTB"
        threat_id = "2147767650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 55 ?? 33 ?? 03 d8 [0-255] 83 45 ?? 04 83 05 ?? ?? ?? ?? 04 8b 45 ?? 3b 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GO_2147767650_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GO!MTB"
        threat_id = "2147767650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 55 ?? 33 ?? 03 d8 40 01 83 45 ?? 04 83 05 ?? ?? ?? ?? 04 8b 45 ?? 3b 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GO_2147767650_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GO!MTB"
        threat_id = "2147767650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {32 c1 2a c1 04 ?? c0 c0 ?? c0 c0 ?? 34 ?? c0 c8 ?? 32 c1 c0 c0 ?? 04 ?? 2a c1 32 c1 32 c1 34 ?? 2c ?? aa 4a 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GO_2147767650_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GO!MTB"
        threat_id = "2147767650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 55 ?? 33 ?? 03 d8 58 02 83 45 ?? 04 83 05 ?? ?? ?? ?? 04 8b 45 ?? 3b 05}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GO_2147767650_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GO!MTB"
        threat_id = "2147767650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 55 ?? 33 ?? 03 d8 c2 01 83 45 ?? 04 83 05 ?? ?? ?? ?? 04 8b 45 ?? 3b 05}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GO_2147767650_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GO!MTB"
        threat_id = "2147767650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 4b a1 ?? ?? ?? ?? 33 18 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 83 c0 04 03 d8 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 03 d8 89 1d ?? ?? ?? ?? 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GO_2147767650_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GO!MTB"
        threat_id = "2147767650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 55 fc 89 55 ?? 0f b6 05 [0-4] 03 45 ?? 89 45 ?? 0f b6 0d [0-4] 8b 55 ?? 2b d1 89 55 ?? 0f b6 05 [0-4] 33 45 ?? 89 45 ?? 0f b6 0d [0-4] 8b 55 ?? 2b d1 89 55 ?? 0f b6 05 [0-4] 8b 4d ?? 2b c8 89 4d ?? 8b 15 [0-4] 03 55 ?? 8a 45 ?? 88 02 e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GO_2147767650_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GO!MTB"
        threat_id = "2147767650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b d8 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82 c8 00 01 02 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 02 01 01 31 33}  //weight: 10, accuracy: Low
        $x_5_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GO_2147767650_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GO!MTB"
        threat_id = "2147767650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 c4 [0-2] 57 8b 4d [0-2] 8b f9 03 f9 33 7d [0-2] 3b f9 76 [0-2] 51 51 57 ff 75 [0-2] e8 [0-4] 59 49 75 [0-2] b8 00 00 00 00 5f c9 c2}  //weight: 1, accuracy: Low
        $x_1_2 = {51 68 00 10 00 00 52 50 ff 93 [0-4] 8b f8 89 bb [0-4] 8b b3 [0-4] 8b 8b [0-4] fc f3 a4 b9 [0-4] 8b 83 [0-4] 68 [0-4] 8f 83 [0-4] 21 8b [0-4] 03 83 [0-4] ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GO_2147767650_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GO!MTB"
        threat_id = "2147767650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 52 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? e8 [0-30] 03 05 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? eb 64 00 a1 ?? ?? ?? ?? 3b 05}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 55 ?? 33 ?? 03 d8}  //weight: 10, accuracy: Low
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GO_2147767650_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GO!MTB"
        threat_id = "2147767650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 c8 00 01 02 a1 ?? ?? ?? ?? 83 e8 0b 03 05 ?? ?? ?? ?? a3 [0-75] 02 01 01 31 33}  //weight: 10, accuracy: Low
        $x_5_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_5_3 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 [0-5] 03 [0-5] 8b [0-5] e8}  //weight: 5, accuracy: Low
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GO_2147767650_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GO!MTB"
        threat_id = "2147767650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 c8 00 01 02 a1 ?? ?? ?? ?? 2d ?? ?? 00 00 03 05 ?? ?? ?? ?? a3 [0-150] 02 01 01 31 33}  //weight: 10, accuracy: Low
        $x_5_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_5_3 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 [0-5] 03 [0-5] 8b [0-5] e8}  //weight: 5, accuracy: Low
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GO_2147767650_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GO!MTB"
        threat_id = "2147767650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 fa 00 01 02 a1 ?? ?? ?? ?? 2d ?? ?? 00 00 03 05 ?? ?? ?? ?? a3 [0-150] 02 01 01 31 33}  //weight: 10, accuracy: Low
        $x_5_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_5_3 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 [0-5] 03 [0-5] 8b [0-5] e8}  //weight: 5, accuracy: Low
        $x_5_4 = {99 03 04 24 13 54 24 04 83 c4 08 [0-30] 8b d0 8b [0-6] e8}  //weight: 5, accuracy: Low
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GO_2147767650_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GO!MTB"
        threat_id = "2147767650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 02 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05 af 00 01 02 a1 [0-15] 03 05 ?? ?? ?? ?? a3 [0-60] 02 01 01 31 33}  //weight: 10, accuracy: Low
        $x_10_2 = {89 10 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05 af 00 01 10 a1 [0-15] 03 05 ?? ?? ?? ?? a3 [0-60] 02 01 01 31 33}  //weight: 10, accuracy: Low
        $x_5_3 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_5_4 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 [0-5] 03 [0-5] 8b [0-5] e8}  //weight: 5, accuracy: Low
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GO_2147767650_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GO!MTB"
        threat_id = "2147767650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 fa 00 2b d8 89 5d ?? 8b 45 ?? 03 45 ?? 8b 55 ?? 02 01 01 31 33}  //weight: 10, accuracy: Low
        $x_5_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_3_3 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 [0-5] 03 [0-5] 8b [0-5] e8}  //weight: 3, accuracy: Low
        $x_3_4 = {99 03 04 24 13 54 24 04 83 c4 08 [0-30] 8b d0 8b [0-6] e8}  //weight: 3, accuracy: Low
        $x_3_5 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 8b 45 ?? 03 45 ?? 8b 4d ?? e8}  //weight: 3, accuracy: Low
        $x_1_6 = "VirtualAlloc" ascii //weight: 1
        $x_1_7 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GO_2147767650_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GO!MTB"
        threat_id = "2147767650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 c8 00 01 02 a1 ?? ?? ?? ?? 2d ?? ?? 00 00 03 05 ?? ?? ?? ?? a3 [0-150] 02 01 01 31 33}  //weight: 10, accuracy: Low
        $x_10_2 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 c8 00 a1 ?? ?? ?? ?? 2d ?? ?? 00 00 03 05 ?? ?? ?? ?? 03 [0-150] 02 01 01 31 33}  //weight: 10, accuracy: Low
        $x_5_3 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_5_4 = {99 03 04 24 13 54 24 04 83 c4 08 [0-30] 8b d0 8b [0-6] e8}  //weight: 5, accuracy: Low
        $x_5_5 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 [0-5] 03 [0-5] 8b [0-5] e8}  //weight: 5, accuracy: Low
        $x_1_6 = "VirtualAlloc" ascii //weight: 1
        $x_1_7 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*))) or
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GP_2147767663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GP!MTB"
        threat_id = "2147767663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DrawThemeIcon" ascii //weight: 1
        $x_1_2 = "ZgfSSwuDvAUqJGdLbOXRSCpBEWcrVWEvHL.dll" ascii //weight: 1
        $x_1_3 = "lGVuEuZmKeYiGcqqkA.dll" ascii //weight: 1
        $x_1_4 = "smmaia.dll" ascii //weight: 1
        $x_1_5 = "PzOVumTqSsdAjArZcqn.dll" ascii //weight: 1
        $x_1_6 = "YixcPNtjteTItxwyMrTUyTbGFRFfHceLRNw.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GP_2147767663_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GP!MTB"
        threat_id = "2147767663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 4b 8b 45 d8 33 18 89 5d a0 [0-50] 03 d8 8b 45 d8 89 18 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 8b 45 d8 83 c0 04 03 45 a4 89 45 d8 8b 45 a8 3b 45 cc 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GP_2147767663_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GP!MTB"
        threat_id = "2147767663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 e4 ff ff 0f 00 59 51 33 0c [0-1] 33 8b [0-4] 83 e0 00 31 c8 59 68 [0-4] 8f 83 [0-4] 21 8b [0-4] 89 4d [0-1] 8b 8b [0-4] 01 c1 51 8b 4d [0-1] 58 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GP_2147767663_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GP!MTB"
        threat_id = "2147767663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 e4 ff ff 0f 00 59 89 4d [0-1] 33 4d [0-1] 0b 8b [0-4] 83 e0 00 09 c8 8b 4d [0-1] 54 c7 04 e4 [0-4] 8f 83 [0-4] 21 8b [0-4] 6a 00 89 3c [0-1] 50 5f 03 bb [0-4] 89 f8 5f ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GP_2147767663_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GP!MTB"
        threat_id = "2147767663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c8 89 4d ?? 0f b6 15 ?? ?? ?? ?? 8b 45 ?? 2b c2 89 45 ?? 0f b6 0d ?? ?? ?? ?? 8b 55 ?? 2b d1 89 55 ?? 0f b6 05 ?? ?? ?? ?? 33 45 ?? 89 45 ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 8a 55 ?? 88 11 e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GP_2147767663_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GP!MTB"
        threat_id = "2147767663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 d2 31 c2 89 93 ?? ?? ?? ?? 8b 55 ?? ff 93 ?? ?? ?? ?? 83 bb ?? ?? ?? ?? 00}  //weight: 10, accuracy: Low
        $x_10_2 = {59 fc 83 bb ?? ?? ?? ?? 00 f3 a4 83 bb ?? ?? ?? ?? 00 75 ?? ff 93 ?? ?? ?? ?? 6a 00 89 34 e4 29 f6 31 c6 89 b3 ?? ?? ?? ?? 5e 57 c7 04 e4 ff ff 0f 00 59 83 bb ?? ?? ?? ?? 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GP_2147767663_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GP!MTB"
        threat_id = "2147767663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {b8 4c 66 44 00 cc cc ff 15 ?? ?? ?? ?? 68 dc 0f 07 10 c3}  //weight: 5, accuracy: Low
        $x_5_2 = {c0 c0 07 68 09 28 07 10 c3}  //weight: 5, accuracy: High
        $x_5_3 = {32 c1 68 4b 0f 07 10 c3}  //weight: 5, accuracy: High
        $x_5_4 = {68 ea 0e 00 00 68 a7 e7 06 10 68 a7 e7 06 10 b8 8c fa 06 10 ff d0}  //weight: 5, accuracy: High
        $x_1_5 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GP_2147767663_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GP!MTB"
        threat_id = "2147767663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec a1 [0-4] a3 [0-4] 8b [0-6] 89 [0-6] 8b [0-6] 8b 02 a3 [0-4] 8b [0-6] 81 [0-6] 89 [0-6] 8b [0-6] 81 [0-6] a1 [0-4] a3 [0-4] 31 0d [0-4] a1 [0-4] c7 05 [0-8] 01 [0-5] 8b 15 [0-4] a1 [0-4] 89 02 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {88 0a 8b 55 ?? 83 c2 ?? 89 55 ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GP_2147767663_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GP!MTB"
        threat_id = "2147767663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff 75 fc ff 75 f8 ff 75 f0 ff 75 f4 ff 35 ?? ?? ?? ?? 6a 01 ff 30 00 8b ?? ?? 03 ?? ?? 89 ?? ?? 83 ?? ?? 04 81 ?? ?? 00 10 00 00}  //weight: 10, accuracy: Low
        $x_5_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_3_3 = {99 03 04 24 13 54 24 04 83 c4 08}  //weight: 3, accuracy: High
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GP_2147767663_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GP!MTB"
        threat_id = "2147767663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "VirtualAllocEx" ascii //weight: 1
        $x_1_2 = "b196b287-bab4-101a-b69c-00aa00341d07" ascii //weight: 1
        $x_1_3 = "RegOpenKeyA" ascii //weight: 1
        $x_10_4 = {8b ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 33 c0 ff 00 04 01 01 01 01 31 32 30 33 [0-200] a1 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 01 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GP_2147767663_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GP!MTB"
        threat_id = "2147767663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 01 ff 25 48 00 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 83 05 ?? ?? ?? 00 04 81 2d ?? ?? ?? 00 00 10 00 00 ff 35 ?? ?? ?? 00 ff 35 ?? ?? ?? 00 ff 35 ?? ?? ?? 00 ff 35 ?? ?? ?? 00 ff 35 ?? ?? ?? 00}  //weight: 10, accuracy: Low
        $x_5_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GP_2147767663_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GP!MTB"
        threat_id = "2147767663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82 c8 00 03 d8 a1 ?? ?? ?? ?? 01 18 [0-5] 8b 1d ?? ?? ?? ?? 03 1d ?? ?? ?? ?? 03 1d ?? ?? ?? ?? 4b 2b d8 [0-5] 03 d8 a1 ?? ?? ?? ?? 02 01 01 31 33}  //weight: 10, accuracy: Low
        $x_5_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GP_2147767663_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GP!MTB"
        threat_id = "2147767663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {57 c7 45 ec 0e dc eb d2 3a d2 74 00 81 6d ec c4 00 00 00 e8 ?? ?? ?? ?? 66 3b c9 74}  //weight: 10, accuracy: Low
        $x_1_2 = {ff 75 0c ff 75 08 eb 00 ff 55 f8}  //weight: 1, accuracy: High
        $x_1_3 = {ff 75 b0 ff 55 f0 3a d2 74}  //weight: 1, accuracy: High
        $x_1_4 = "4f3f9b0500ecae080000000080488bc4488958084c8948" ascii //weight: 1
        $x_1_5 = {c6 45 ba 53 80 45 ba 19 66 3b f6 74}  //weight: 1, accuracy: High
        $x_1_6 = {c6 45 be 59 80 45 be 10 3a c9 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GP_2147767663_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GP!MTB"
        threat_id = "2147767663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b d8 01 5d ?? 8b 45 ?? 3b 45 ?? 0f 82 c8 00 8b d8 8b 45 ?? 03 45 ?? 2d 67 2b 00 00 03 45 ?? 03 d8 [0-75] 02 01 01 31 33}  //weight: 10, accuracy: Low
        $x_5_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_5_3 = {8b 55 e0 03 55 ?? 8b 45 ?? 03 45 ?? 8b 4d ?? e8}  //weight: 5, accuracy: Low
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GP_2147767663_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GP!MTB"
        threat_id = "2147767663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "VirtualProtect" ascii //weight: 1
        $x_1_2 = "b196b287-bab4-101a-b69c-00aa00341d07" ascii //weight: 1
        $x_1_3 = "RegOpenKeyA" ascii //weight: 1
        $x_1_4 = {03 f0 8b 45 ?? 03 30 8b 4d ?? 89 31 8b 55 ?? 8b 02 2d bc 01 00 00 8b 4d ?? 89 01 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_5 = {8a 0c 32 88 0c 38 8b 55 ?? 83 c2 ?? 89 55 ?? eb ?? 5f 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GQ_2147767664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GQ!MTB"
        threat_id = "2147767664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 8b 45 d8 83 c0 04 03 45 a4 89 45 d8 8b 45 a8 3b 45 cc 0f 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GQ_2147767664_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GQ!MTB"
        threat_id = "2147767664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {49 8d 41 01 03 c7 a3 ?? ?? ?? ?? 8a 04 16 88 02 42 8b 1d ?? ?? ?? ?? 8b c3 2b c7 66 83 3d ?? ?? ?? ?? 00 8d 78 ?? 74 ?? b0 b9 2a c3 a2 ?? ?? ?? ?? 85 c9 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GQ_2147767664_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GQ!MTB"
        threat_id = "2147767664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {59 fc 83 bb ?? ?? ?? ?? 00 f3 a4 83 bb ?? ?? ?? ?? 00 75 ?? ff 93 ?? ?? ?? ?? 89 [0-2] 29 f6 09 c6 89 b3 ?? ?? ?? ?? 8b 75 ?? 57 c7 04 e4 ff ff 0f 00 59 83 bb ?? ?? ?? ?? 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GQ_2147767664_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GQ!MTB"
        threat_id = "2147767664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 53 [0-2] a1 [0-4] a3 [0-4] 8b [0-5] 8b [0-2] 89 [0-5] 8b [0-5] a1 [0-4] a3 [0-4] b8 [0-4] b8 [0-4] a1 [0-4] 8b d8 33 d9 c7 05 [0-4] 00 00 00 00 01 [0-5] a1 [0-4] 8b 0d [0-4] 89 08 5b 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GQ_2147767664_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GQ!MTB"
        threat_id = "2147767664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 73 16 00 00 ff 35 ?? ?? ?? ?? b8 73 16 00 00 ff 35 ?? ?? ?? ?? b8 73 16 00 00 ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? b8 01 00 00 00 50 ff 25}  //weight: 10, accuracy: Low
        $x_5_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GQ_2147767664_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GQ!MTB"
        threat_id = "2147767664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82 c8 00 03 05 ?? ?? ?? ?? 48 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 01 02 [0-5] 8b d8 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 d8 [0-5] 2b d8 a1 ?? ?? ?? ?? 02 01 01 31 33}  //weight: 10, accuracy: Low
        $x_5_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GQ_2147767664_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GQ!MTB"
        threat_id = "2147767664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 8b 0d [0-8] 89 0d [0-8] 8b 0d [0-8] 81 e9 [0-8] 51 c7 05 [0-8] ff 05 [0-8] ff 35 [0-8] ff 35 [0-8] ff 35 [0-8] a1 [0-8] ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 53 57 a1 [0-4] a3 [0-4] 8b 0d [0-4] 8b 11 89 15 [0-10] a1 [0-4] 50 8f 05 [0-4] 8b 3d [0-15] 8b c7 eb 00 eb 00 eb 00 eb 00 eb 00 eb 00 bb}  //weight: 1, accuracy: Low
        $x_1_3 = {8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b c8 8b d1 89 15 [0-4] a1 [0-4] 8b 0d [0-4] 89 08 [0-2] 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Qakbot_GR_2147767767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GR!MTB"
        threat_id = "2147767767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c0 2b 15 ?? ?? ?? ?? 1b 05 [0-50] 8b 0d ?? ?? ?? ?? 83 c1 ?? 8b 15 ?? ?? ?? ?? 83 d2 00 33 c0 03 4d ?? 13 d0 66 89 4d fc 8b 7d f0 05 ?? ?? ?? ?? ff e7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GR_2147767767_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GR!MTB"
        threat_id = "2147767767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fc f3 a4 57 c7 04 e4 ff ff [0-2] 59 56 83 e6 00 0b b3 [0-4] 83 e0 00 09 f0 5e 68 [0-4] 8f 83 [0-4] 21 8b [0-4] 6a 00 01 [0-2] 50 5a 03 93 [0-4] 89 d0 5a ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GR_2147767767_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GR!MTB"
        threat_id = "2147767767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 68 00 10 00 00 52 50 ff 93 [0-6] 89 bb [0-4] 8b b3 [0-4] 8b 8b [0-4] fc f3 a4 b9 ff ff 0f 00 8b 83 [0-4] 68 [0-4] 8f 83 [0-4] 21 8b [0-4] 03 83 [0-4] ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GR_2147767767_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GR!MTB"
        threat_id = "2147767767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 53 eb 00 a1 [0-4] a3 [0-4] 8b [0-5] 8b ?? 89 [0-5] 8b [0-5] a1 [0-4] a3 [0-30] 33 d9 c7 05 [0-4] 00 00 00 00 01 ?? [0-4] a1 [0-4] 8b 0d [0-4] 89 08 5b 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GR_2147767767_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GR!MTB"
        threat_id = "2147767767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 04 a3 ?? ?? ?? ?? 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82 25 00 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 33 02 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GR_2147767767_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GR!MTB"
        threat_id = "2147767767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 ea 01 89 55 ?? 85 c9 74 ?? 8b 45 ?? 83 e8 ?? 2b 45 ?? a3 ?? ?? ?? ?? 8b 4d ?? 8b 55 ?? 8a 02 88 01 8b 4d ?? 83 c1 01 89 4d ?? 8b 55 ?? 83 c2 01 89 55 ?? a1 ?? ?? ?? ?? 83 e8 ?? 2b 05 ?? ?? ?? ?? 89 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GR_2147767767_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GR!MTB"
        threat_id = "2147767767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 d8 8b 45 ?? 02 01 01 31 33 ?? 89 5d ?? 8b 45 ?? 8b 55 ?? 89 10 33 c0 89 45 ?? 8b 45 ?? 83 c0 ?? 03 45 ?? 89 45 [0-8] 8b 5d ?? 83 c3 04 03 5d ?? 2b d8}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 00 8b 55 ?? 03 55 ?? 03 55 ?? 4a 02 01 01 31 33 ?? 89 45 ?? 8b 45 ?? 8b 55 ?? 89 10 33 c0 89 45 [0-8] 8b 5d ?? 83 c3 04 03 5d ?? 2b d8}  //weight: 10, accuracy: Low
        $x_5_3 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_MK_2147767774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MK!MTB"
        threat_id = "2147767774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 83 24 e4 ?? 31 3c e4 6a 00 89 3c e4 29 ff 0b 7d 08 89 fe 5f 53 33 1c e4 33 5f ?? 83 e1 00 31 d9 5b 53 8b 5f ?? 56 8f 45 f8 01 5d f8 ff 75 f8 5e 5b 8b 7f 0c 6a 00 01 2c e4 57 5d 03 ab ?? ?? ?? 00 89 ef 5d f3 a4 81 e7 ?? ?? ?? ?? 0b 3c e4 83 c4 ?? 50 89 f8 81 c0 ?? ?? ?? ?? 89 c7 58 ff 4d fc 75 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_ZX_2147771364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.ZX!MTB"
        threat_id = "2147771364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 5f 33 00 00 85 c0 74 59 8b 4d f8 3b 0d ?? ?? ?? ?? 72 02 eb 4c 8b 45 f8 33 d2 b9 ?? ?? 00 00 f7 f1 85 d2 75 0e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_ZX_2147771364_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.ZX!MTB"
        threat_id = "2147771364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 89 45 f4 8b 0d ?? ?? ?? ?? 03 4d fc 89 0d ?? ?? ?? ?? 8b 55 f4 89 55 e8 8b 45 e8 50 68 ?? ?? ?? 00 e8 ?? ?? ?? ?? 83 c4 08 8b 4d f0 8b 55 fc 8d 84 0a ?? ?? ?? ?? 89 45 ec 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 55 ec 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d fc 83 c1 04 89 4d fc 8b 55 fc 3b 15 ?? ?? ?? ?? 72 02 eb 0d b8 ?? 00 00 00 85 c0 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GB_2147772346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GB!MTB"
        threat_id = "2147772346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 02 8b 45 c4 03 45 a4 03 45 9c 2b 45 9c 89 45 a0 8b 45 d8 8b 00 8b 55 a0 03 55 9c 2b 55 9c 2b 55 9c 03 55 9c 33 c2 89 45 a0 8b 45 a0 03 45 9c 2b 45 9c 8b 55 d8 89 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GB_2147772346_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GB!MTB"
        threat_id = "2147772346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 02 88 01 8b 4d ?? 83 c1 01 89 4d ?? 8b 55 ?? 83 c2 01 89 55 ?? 8b 45 ?? 2d 44 49 00 00 03 45 fc 2b 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 c8 89 0d ?? ?? ?? ?? c7 45 ?? 01 00 00 00 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GB_2147772346_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GB!MTB"
        threat_id = "2147772346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b7 f3 02 c6 02 c2 0f b6 c0 6b c0 ?? 2b f0 89 35 [0-4] 8a 15 [0-4] 8d 87 [0-4] 8b 7c 24 ?? 8a f3 80 c2 ?? a3 [0-4] 02 d6 8a 35 [0-4] 89 07 83 c7 04 83 6c 24 ?? 01 89 7c 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GB_2147772346_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GB!MTB"
        threat_id = "2147772346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 da 2b d8 83 c3 01 89 1d ?? ?? ?? ?? 8a c1 b3 ?? f6 eb 2a c2 8a d0 83 7c 24 ?? 00 75}  //weight: 10, accuracy: Low
        $x_10_2 = {8b cb 6b c9 ?? 2b c8 2b c8 8d 4c 19 01 8b 6c 24 ?? 6b c0 ?? 81 c6 ?? ?? ?? ?? 2b c7 89 75 00 03 c2 83 c5 04 83 6c 24 ?? 01}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GB_2147772346_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GB!MTB"
        threat_id = "2147772346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "webinjects.cb" ascii //weight: 10
        $x_1_2 = "data_inject" ascii //weight: 1
        $x_1_3 = "data_before" ascii //weight: 1
        $x_1_4 = "data_after" ascii //weight: 1
        $x_1_5 = "data_end" ascii //weight: 1
        $x_1_6 = "pid=[" ascii //weight: 1
        $x_1_7 = "cookie=[" ascii //weight: 1
        $x_1_8 = "exe=[" ascii //weight: 1
        $x_1_9 = "ua=[" ascii //weight: 1
        $x_1_10 = "%u.%u.%u.%u" ascii //weight: 1
        $x_1_11 = "Mozilla\\Firefox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GB_2147772346_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GB!MTB"
        threat_id = "2147772346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "stager_1.dll" ascii //weight: 10
        $x_10_2 = "DllRegisterServer" ascii //weight: 10
        $x_10_3 = "Hello qqq" ascii //weight: 10
        $x_1_4 = "OutputDebugStringA" ascii //weight: 1
        $x_1_5 = "memcpy" ascii //weight: 1
        $x_1_6 = "memset" ascii //weight: 1
        $x_1_7 = "SystemDrive" ascii //weight: 1
        $x_1_8 = "USERPROFILE" ascii //weight: 1
        $x_1_9 = "CreatePipe" ascii //weight: 1
        $x_1_10 = "GetCurrentProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GB_2147772346_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GB!MTB"
        threat_id = "2147772346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "stager_1.dll" ascii //weight: 10
        $x_10_2 = "DllRegisterServer" ascii //weight: 10
        $x_1_3 = "https://" ascii //weight: 1
        $x_1_4 = "memcpy" ascii //weight: 1
        $x_1_5 = "LookupAccountNameW" ascii //weight: 1
        $x_1_6 = "SystemDrive" ascii //weight: 1
        $x_1_7 = "memset" ascii //weight: 1
        $x_1_8 = "GetUserProfileDirectoryW" ascii //weight: 1
        $x_1_9 = "USERPROFILE" ascii //weight: 1
        $x_1_10 = "OpenProcessToken" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_GB_2147772346_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GB!MTB"
        threat_id = "2147772346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "b196b287-bab4-101a-b69c-00aa00341d07" ascii //weight: 1
        $x_1_2 = {03 f0 8b 45 ?? 03 30 8b 4d ?? 89 31 8b 55 ?? 8b 02 2d ?? ?? 00 00 8b 4d ?? 89 01 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 14 31 88 14 38 8b 45 ?? 83 c0 ?? 89 45 [0-6] 5f 5e 8b e5 5d c3 28 00 03 45 ?? 8b}  //weight: 1, accuracy: Low
        $x_1_4 = {8b ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 ff 00 04 01 01 01 01 31 32 30 33 [0-200] c7 05 ?? ?? ?? ?? 00 00 00 00 01 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Qakbot_GB_2147772346_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GB!MTB"
        threat_id = "2147772346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be ac 00 00 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 94 01 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2d be ac 00 00 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {03 f0 8b 45 ?? 03 30 8b 4d ?? 89 31 8b 55 ?? 8b 02 2d ?? ?? ?? ?? 8b 4d ?? 89 01 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 0c 32 88 0c 38 8b 55 ?? 83 c2 ?? 89 55 ?? eb ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 5f 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_4 = {89 08 5f 5d c3 ff 00 04 01 01 01 01 31 32 30 33 [0-200] c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Qakbot_AV_2147773338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AV!MTB"
        threat_id = "2147773338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 55 fc 5a d3 c0 8a fc 8a e6 d3 cb ff 4d fc 75 f3 29 c9 0b 0c e4 83 c4 04 89 4d f8 83 e1 00 31 d9 83 e0 00 31 c8 8b 4d f8 aa 49 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AV_2147773338_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AV!MTB"
        threat_id = "2147773338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {03 d8 8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 8b 45 d8 83 c0 04 03 45 a4 89 45 d8 8b 45 a8 3b 45 cc 0f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 4d 1e 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 01 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 54 1b 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 01 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 e3 14 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 01 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 eb 14 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 01 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 f8 83 c6 43 8a 04 2a 88 02 8b c7 2b c1 42 83 c0 43 89 54 24 ?? 0f b7 c8 2b ce 83 c1 40 39 35 ?? ?? ?? ?? 77}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 cf 0d 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 01 5d ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 01 45 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 8a a5 08 00 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 d7 11 00 00 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 8b 00 8b 15 ?? ?? ?? ?? 03 55 ?? 03 55 ?? 33 c2 03 d8 68 d7 11 00 00 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 8a a5 08 00 03 45 ?? 8b 55 ?? 31 02 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 45 ?? 8b 45 ?? 3b 45 ?? 0f 83 ?? ?? ?? ?? 68 d8 11 00 00 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 8b 00 03 45 ?? 03 d8 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 1c 17 a3 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 8b 94 0f ?? ?? ?? ?? 81 c2 f0 07 07 01 89 94 0f ?? ?? ?? ?? 83 c1 04 81 f9 80 05 00 00 8d 74 1e ?? 89 15 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 db 03 fb 89 3d ?? ?? ?? ?? 8b 84 0e ?? ?? ?? ?? 05 4c 6a 06 01 a3 ?? ?? ?? ?? 89 84 0e ?? ?? ?? ?? 83 c6 04 0f b7 05 ?? ?? ?? ?? 05 da 9d 00 00 03 c7 81 fe 60 0b 00 00 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 45 ?? 8b 45 ?? 3b 45 ?? 0f 83 ?? ?? ?? ?? 68 57 15 00 00 6a 00 e8 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b 12 03 55 ?? 03 c2 8b 15 ?? ?? ?? ?? 89 02 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 01 5d ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 01 45 ?? e9 ?? ?? ?? ?? 33 c0 89 45 ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 0f 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 8b 55 ?? 03 55 ?? 03 55 ?? 33 c2 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 89 18 a1 ?? ?? ?? ?? 83 c0 04 a3 ?? ?? ?? ?? 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 8a a5 08 00 03 45 ?? 8b 55 ?? 31 02 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 45 ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 0f 83}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d8 8b 45 ?? 03 45 ?? 03 45 ?? 03 d8 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 45 ?? 8b 45 ?? 3b 45 ?? 0f 83 ?? ?? ?? ?? 8b 45 ?? 8b 55 ?? 01 02 68 3b 11 00 00 6a 00 e8 ?? ?? ?? ?? 8b d8 8b 45 ?? 05 8a a5 08 00 03 45 ?? 03 d8 68 3b 11 00 00 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_18
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c8 8b 55 ?? 03 55 ?? 8b 45 ?? 03 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 01 45 ?? eb ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_19
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 45 ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 73}  //weight: 1, accuracy: Low
        $x_1_2 = {2b d8 8b 45 ?? 89 18 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_20
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 2d 16 00 00 6a 00 e8 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {68 2d 16 00 00 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 8b 00 8b 15 ?? ?? ?? ?? 81 c2 8a a5 08 00 03 55 ?? 33 c2 03 d8 68 2d 16 00 00 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_21
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 cf 0d 00 00 6a 00 e8 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {68 cf 0d 00 00 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 8b 00 8b 15 ?? ?? ?? ?? 81 c2 8a a5 08 00 03 55 ?? 33 c2 03 d8 68 cf 0d 00 00 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_22
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 45 ?? 33 c9 8b 55 ?? 8b 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 3b 45 ?? 73 ?? 8b 55 ?? 03 55 ?? 8b 45 ?? 03 45 ?? 8b 4d ?? e8 ?? ?? ?? ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 01 45 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_23
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 01 5d ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 01 45 ?? e9 ?? ?? ?? ?? c7 45 a8 8a a5 08 00 8b 45 ?? 3b 45 ?? 73 ?? 8b 45 ?? 8b 55 ?? 01 02 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GKM_2147773497_24
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GKM!MTB"
        threat_id = "2147773497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 01 5d ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 01 45 ?? eb ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 73 ?? 8b 45 ?? 8b 55 ?? 01 02 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PC_2147773912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PC!MTB"
        threat_id = "2147773912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ole3454.dll" ascii //weight: 1
        $x_1_2 = "\\Dll\\out.pdb" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_4_4 = {d3 fa 89 15 ?? ?? ?? ?? 8b 4d ?? 2b 4d ?? 2b 0d ?? ?? ?? ?? 03 4d ?? 8b 45 ?? d3 f8 33 45 ?? 8b 55 ?? 8b 0d ?? ?? ?? ?? d3 fa 33 55 ?? 8b 4d ?? 2b 4d ?? 8b 35 ?? ?? ?? ?? d3 e6 33 d6 3b c2 7f}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GS_2147776916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GS!MTB"
        threat_id = "2147776916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f af c1 2b 45 ?? 66 89 45 ?? 0f b6 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 0f b7 45 ?? 83 c0 ?? 2b 45 ?? 66 89 45 ?? 8b 75 ?? 81 c2 ?? ?? ?? ?? 42 ff e6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GS_2147776916_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GS!MTB"
        threat_id = "2147776916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 04 a3 ?? ?? ?? ?? 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82 2d 00 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 33 02 a3 [0-15] 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AA_2147778946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AA!MTB"
        threat_id = "2147778946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d3 c0 8a fc 8a e6 d3 cb ff 4d ?? 75 ?? 89 4d ?? 2b 4d ?? 09 d9 83 e0 00 09 c8 8b 4d ?? 59 aa 49 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AA_2147778946_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AA!MTB"
        threat_id = "2147778946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 1c 30 8b 55 ?? d3 c2 23 d3 ac 0a c2 88 07 47 ff 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 c0 8a fc 8a e6 d3 cb ff 4d ?? 75 ?? 59 8b c3 aa 49 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_VIP_2147781069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.VIP!MTB"
        threat_id = "2147781069"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 03 45 ec 03 d8 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 89 18 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 d8 03 45 ac 03 45 ec 03 d8 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PD_2147782359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PD!MTB"
        threat_id = "2147782359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c8 89 4d ?? 0f b6 15 ?? ?? ?? ?? 8b 45 ?? 2b c2 89 45 ?? 0f b6 0d ?? ?? ?? ?? 8b 55 ?? 2b d1 89 55 ?? 0f b6 05 ?? ?? ?? ?? 33 45 ?? 89 45 ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 8a 55 ?? 88 11 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_W_2147782484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.W!MTB"
        threat_id = "2147782484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Burnstar" ascii //weight: 3
        $x_3_2 = "Personfind" ascii //weight: 3
        $x_3_3 = "Plantcover" ascii //weight: 3
        $x_3_4 = "oil\\patter\\those.pdb" ascii //weight: 3
        $x_3_5 = "IsDebuggerPresent" ascii //weight: 3
        $x_3_6 = "InterlockedPushEntrySList" ascii //weight: 3
        $x_3_7 = "OutputDebugStringA" ascii //weight: 3
        $x_3_8 = "IsProcessorFeaturePresent" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_A_2147782503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.A!!Qakbot.A"
        threat_id = "2147782503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "Qakbot: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 00 33 00 30 00 38 00}  //weight: 1, accuracy: High
        $x_1_2 = {03 00 33 00 31 00 31 00}  //weight: 1, accuracy: High
        $x_1_3 = {03 00 31 00 31 00 38 00}  //weight: 1, accuracy: High
        $x_1_4 = {03 00 35 00 32 00 34 00}  //weight: 1, accuracy: High
        $x_10_5 = {01 23 45 67 c7 44 24 ?? 89 ab cd ef c7 44 24 ?? fe dc ba 98 c7 44 24}  //weight: 10, accuracy: Low
        $x_10_6 = {03 ce 03 c1 33 d2 6a ?? 5b f7 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? 46}  //weight: 10, accuracy: Low
        $x_10_7 = {48 f7 d8 1b c0 25 ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_DA_2147782538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DA"
        threat_id = "2147782538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 20 00 2e 00 2e 00 5c 00 [0-32] 2c 00 64 00 6c 00 6c 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 73 00 65 00 72 00 76 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_2 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 20 00 2e 00 2e 00 5c 00 [0-32] 2c 00 73 00 74 00 61 00 72 00 74 00 77 00}  //weight: 1, accuracy: Low
        $x_1_3 = "regsvr32 -s ..\\" wide //weight: 1
        $x_1_4 = "regsvr32 ..\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qakbot_DB_2147782539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DB"
        threat_id = "2147782539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "iroto.tio" wide //weight: 10
        $x_10_2 = "lertio.cersw" wide //weight: 10
        $x_1_3 = "regsvr32.exe -s" wide //weight: 1
        $x_1_4 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 [0-4] 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_5 = "nt authority\\system" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_F_2147782784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.F!ibt"
        threat_id = "2147782784"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c9 8f 45 ?? 0b 4d ?? 89 55 ?? 89 ca 01 c2 52 8b 55 ?? 58 89 7d ?? 83 e7 00 33 bb ?? ?? ?? ?? 83 e1 00 31 f9 8b 7d ?? 39 c1 76 24 8d 83 ?? ?? ?? ?? 83 65 ?? ?? ff 75 ?? 31 04 ?? 8d 83 ?? ?? ?? ?? 53 83 24 ?? ?? 31 04 ?? ff 93}  //weight: 1, accuracy: Low
        $x_1_2 = {50 5e 01 ce 89 f0 5e 89 55 ?? 33 55 ?? 33 93 ?? ?? ?? ?? 83 e1 00 09 d1 8b 55 ?? 39 c1 76 ?? 8d 83 ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? ff 75 ?? 31 04 ?? 8d 83 ?? ?? ?? ?? 83 65 ?? ?? ff 75 ?? 09 04 ?? ff 93}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_W_2147782943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.W"
        threat_id = "2147782943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {2b cb 89 4d fc 25 00 (6a 5a|33 d2) 8b c1 5e f7 f6 8b 45 ?? 8a 04 02 [0-3] 32 04 ?? 74 08 41 3b 4d ?? 72}  //weight: 10, accuracy: Low
        $x_10_3 = {5f 5e 5b c9 c3 2a 00 8b 4d ?? 8b 45 ?? 03 ce 03 c1 33 d2 6a 5a 5b f7 f3 8b 45 ?? 8a 04 02 32 04 37 46 88 01 3b 75 fc 72 de 8b 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_U_2147782945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.U"
        threat_id = "2147782945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {08 01 00 00 32 ?? ?? 04 88 ?? ?? ?? 3b ?? 72 e8 1a 00 76 18 8b ?? 83 ?? 03 8a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BN_2147783309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BN!MTB"
        threat_id = "2147783309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 1c 28 83 c5 04 0f af 5e 70 8b 86 ?? ?? ?? ?? 8b d3 c1 ea 08 88 14 01 8b 86 ?? ?? ?? ?? 2b 86 ?? ?? ?? ?? ff 86 ?? ?? ?? ?? 05 ?? ?? ?? ?? 01 86 ?? ?? ?? ?? 8b 86 ?? ?? ?? ?? 8b 8e ?? ?? ?? ?? 83 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BN_2147783309_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BN!MTB"
        threat_id = "2147783309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 e8 8b 55 ec 01 02 8b 45 b8 03 45 e8 89 45 b4 68 [0-4] e8 [0-4] 8b d8 8b 45 d8 03 45 b4 03 d8 68 [0-4] e8 [0-4] 03 d8 8b 45 ec 31 18 68 [0-4] e8 [0-4] 8b d8 8b 45 e8 83 c0 04 03 d8 68 [0-4] e8 [0-4] 2b d8 89 5d e8 8b 45 ec 83 c0 04 89 45 ec 8b 45 e8 3b 45 e4 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PG_2147783653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PG!MTB"
        threat_id = "2147783653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 2c 03 45 [0-48] 89 ?? b0 8b 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 8b 45 ?? 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AL_2147784835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AL!MTB"
        threat_id = "2147784835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 47 4c 37 30 00}  //weight: 1, accuracy: High
        $x_1_2 = {ac 02 c3 32 c3 c0 c8 08 aa 49 e9}  //weight: 1, accuracy: High
        $x_1_3 = {8b 55 f0 68 50 3c 0a 60 68 5a 6e 00 00 6a 00 e8 ?? ?? ?? ?? 5a ff d0 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AL_2147784835_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AL!MTB"
        threat_id = "2147784835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 02 8b 45 ?? 2d 80 0d 00 00 03 45 ?? 89 45 ?? 8b 45 ?? 03 45 ?? 8b 55 ?? 31 02 [0-32] e8 40 00 8b 45 ?? 8b 55}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_Z_2147794328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.Z"
        threat_id = "2147794328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "201"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {c7 45 10 5a 00 00 00 33 d2 8b c6 f7 75 10 8a 04 0a 8b 55 fc 3a 04 16 74 11 46 3b f3 72 e9}  //weight: 100, accuracy: High
        $x_100_3 = {33 d2 8b c7 f7 75 10 8a 04 0a 8b 55 fc 32 04 17 88 04 3b 47 83 ee 01 75 e7 8b 4d f8 eb b6}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PAA_2147794418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PAA!MTB"
        threat_id = "2147794418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 55 fc 8b 45 fc c1 f8 02 89 45 fc 8b 55 fc 2b 55 10 03 55 fc 8b 4d fc d3 fa 8b 4d fc d3 fa 8b 0d 24 fe 05 10 0f af 0d 8c fd 05 10 a1 d0 fd 05 10 d3 f8 8b 4d 14 d3 e0 33 d0 8b 45 fc 2b 45 08 8b 4d fc 03 4d 18 03 4d 20 03 4d 08 d3 e0 8b 4d fc d3 e0}  //weight: 1, accuracy: High
        $x_1_2 = {8b 0d 28 fe 05 10 d3 e2 33 c2 8b 55 fc 2b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 0d 44 fe 05 10 d3 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PAA_2147794418_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PAA!MTB"
        threat_id = "2147794418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Iv_encryption_init_info_add_side_data" ascii //weight: 1
        $x_1_2 = "Iv_frame_set_best_effort_timestamp" ascii //weight: 1
        $x_1_3 = "Iv_xtea_le_crypt" ascii //weight: 1
        $x_1_4 = "Ivpriv_slicethread_create" ascii //weight: 1
        $x_1_5 = "Motd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SA_2147794427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SA"
        threat_id = "2147794427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 [0-5] 2d 00 73 00 69 00 6c 00 65 00 6e 00 74 00 [0-5] 2e 00 2e 00 5c 00 78 00 65 00 72 00 74 00 69 00 73 00 [0-1] 2e 00 64 00 6c 00 6c 00}  //weight: 10, accuracy: Low
        $x_10_2 = {72 65 67 73 76 72 33 32 [0-5] 2d 73 69 6c 65 6e 74 [0-5] 2e 2e 5c 78 65 72 74 69 73 [0-1] 2e 64 6c 6c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qakbot_AY_2147794596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AY!MTB"
        threat_id = "2147794596"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b c7 f7 75 ?? 8a 04 0a 8b 55 ?? 32 04 17 88 04 3b 47 83 ee 01 75}  //weight: 1, accuracy: Low
        $x_1_2 = "Qkkbal" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AY_2147794596_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AY!MTB"
        threat_id = "2147794596"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {c1 ea 08 88 14 01 ff 46 70 8b 46 20 2d [0-4] 0f af 86 80 00 00 00 89 86 80 00 00 00 8b 46 0c 8d 88 6a 6c 11 00 0b c8 89 4e 0c 8b 4e 70 8b 86 94 00 00 00 88 1c 01 b8 [0-4] ff 46 70 2b 86 c4 00 00 00 01 46 2c 8b 46 68 35 d5 fc 13 00 29 46 48 8b 86 80 00 00 00 09 86 c4 00 00 00 8b 86 a0 00 00 00 01 86 88 00 00 00 81 ff [0-4] 0f}  //weight: 3, accuracy: Low
        $x_2_2 = "DllRegisterServer" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GY_2147794788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GY!MTB"
        threat_id = "2147794788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 83 e6 00 0b b3 ?? ?? ?? ?? 83 e1 00 31 f1 5e fc f3 a4 52 c7 04 e4 ff ff 0f 00 59 83 bb ?? ?? ?? ?? 00 75}  //weight: 10, accuracy: Low
        $x_10_2 = {83 c4 04 81 e0 00 00 00 00 8f 45 f8 33 45 f8 8f 83 ?? ?? ?? ?? 21 8b ?? ?? ?? ?? 01 83 ?? ?? ?? ?? 83 bb ?? ?? ?? ?? 00 75 ?? ff 93 ?? ?? ?? ?? 50 8f 45 fc ff 75 fc 8f 83 ?? ?? ?? ?? ff a3 ?? ?? ?? ?? e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GY_2147794788_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GY!MTB"
        threat_id = "2147794788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ddfnbdfndnddndfdbdf" ascii //weight: 1
        $x_1_2 = "sdfsdfsd" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "DllUnregisterServer" ascii //weight: 1
        $x_1_5 = "pinnigrada" ascii //weight: 1
        $x_1_6 = "sophomorically" ascii //weight: 1
        $x_1_7 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PK_2147794866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PK!MTB"
        threat_id = "2147794866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d8 8b 45 ?? 33 18 89 5d ?? 8b 45 ?? 8b 55 ?? 89 02 33 c0 89 45 ?? 8b 45 ?? 83 c0 04 03 45 ?? 89 45 ?? 8b 45 ?? 83 c0 04 03 45 ?? 89 45 ?? 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_J_2147794882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.J"
        threat_id = "2147794882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 10 68 26 09 00 00 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 8b 00 8b 15 ?? ?? ?? ?? 81 c2 8a a5 08 00 03 15 ?? ?? ?? ?? 33 c2 03 d8 68 26 09 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 a1 ?? ?? ?? ?? 89 18 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 72 98}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AYE_2147795824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AYE!MTB"
        threat_id = "2147795824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 e5 00 09 c5 83 a3 f4 53 43 00 00 31 ab f4 53 43 00 5d 81 e0 00 00 00 00 8f 45 fc 33 45 fc 89 5d fc}  //weight: 1, accuracy: High
        $x_1_2 = {83 a3 2c 51 43 00 00 31 8b 2c 51 43 00 8b 4d fc 29 c0 33 04 e4 83 c4 04 c7 83 00 50 43 00 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AB_2147796018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AB!MTB"
        threat_id = "2147796018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b d1 89 55 ?? a1 ?? ?? ?? ?? 03 45 ?? 8a 4d ?? 88 08 e9 30 00 89 45 ?? 0f b6 0d ?? ?? ?? ?? 8b 55}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AB_2147796018_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AB!MTB"
        threat_id = "2147796018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b d0 4a a1 ?? ?? ?? ?? 89 10 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 2b d8 4b 6a 00 e8 ?? ?? ?? ?? 2b d8 4b 6a 00 e8 ?? ?? ?? ?? 03 d8 a1 ?? ?? ?? ?? 33 18 89 1d ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_RR_2147796808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RR!MTB"
        threat_id = "2147796808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {29 1f 8a c5 83 5f 04 00 83 ef 08 f6 e9 02 c3 f6 ed 8a c8 02 cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BZ_2147797088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BZ!MTB"
        threat_id = "2147797088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hango_fc_decoder_get_glyph" ascii //weight: 1
        $x_1_2 = "Hango_fc_font_create_base_metrics_for_context" ascii //weight: 1
        $x_1_3 = "Hango_fc_font_kern_glyphs" ascii //weight: 1
        $x_1_4 = "Hango_fc_font_key_get_context_key" ascii //weight: 1
        $x_1_5 = "Hango_fc_font_unlock_face" ascii //weight: 1
        $x_1_6 = "Hango_ft2_font_get_kerning" ascii //weight: 1
        $x_1_7 = "Hango_ot_ruleset_position" ascii //weight: 1
        $x_1_8 = "Hango_ft2_render_transformed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DA_2147797339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DA!MTB"
        threat_id = "2147797339"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d e8 83 e9 37 0f b7 45 f8 99 03 c8 88 4d ff 8b 15 ?? ?? ?? ?? 81 c2 d4 b4 08 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 f4 8b 0d ?? ?? ?? ?? 89 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DA_2147797339_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DA!MTB"
        threat_id = "2147797339"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c8 8b 45 08 eb ?? 0f b6 08 8b 45 fc eb ?? 40 89 45 fc eb}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 08 03 45 fc eb ?? 55 8b ec eb ?? 99 f7 7d 14 eb ?? 8b 45 10 0f b6 04 10 eb c7 03 45 fc 88 08 eb}  //weight: 2, accuracy: Low
        $x_1_3 = "aorbis_synthesis_trackonly" ascii //weight: 1
        $x_1_4 = "aorbis_synthesis_blockin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DB_2147797340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DB!MTB"
        threat_id = "2147797340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d e8 2b c8 8b 15 ?? ?? ?? ?? 2b d1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 05 7c 13 0e 01 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d f8 8b 15 ?? ?? ?? ?? 89 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DB_2147797340_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DB!MTB"
        threat_id = "2147797340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {40 03 d8 a1 [0-4] 89 18 a1 [0-4] 03 05 [0-4] a3 [0-4] 6a 00 e8 [0-4] 03 05 [0-4] 40 8b 15 [0-4] 33 02 a3 [0-4] a1 [0-4] 8b 15 [0-4] 89 10 8b 45 f8 83 c0 04 89 45 f8 33 c0 a3 [0-4] a1 [0-4] 83 c0 04 03 05 [0-4] a3 [0-4] 8b 45 f8 3b 05 [0-4] 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DC_2147797353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DC!MTB"
        threat_id = "2147797353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 4d fc 2b c1 a3 ?? ?? ?? ?? 0f b7 55 fc 0f af 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 66 89 55 fc a1 ?? ?? ?? ?? 05 04 b0 01 01 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d f8 8b 15 ?? ?? ?? ?? 89 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DC_2147797353_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DC!MTB"
        threat_id = "2147797353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "l?0API@ScScript@@IAE@AAVEngine@1@H@Z" ascii //weight: 1
        $x_1_2 = "l?0BreakpointInfo@ScScript@@QAE@ABV01@@Z" ascii //weight: 1
        $x_1_3 = "l?0Debugger@ScScript@@QAE@ABV01@@Z" ascii //weight: 1
        $x_1_4 = "l?0HiliteAPI@ScScript@@AAE@AAVEngine@1@@Z" ascii //weight: 1
        $x_1_5 = "l?_7ValidateData@ScScript@@6B@" ascii //weight: 1
        $x_1_6 = "l_isUInteger@DataPool@ScScript@@ABE_NH@Z" ascii //weight: 1
        $x_1_7 = "next" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DD_2147797397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DD!MTB"
        threat_id = "2147797397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "DrawThemeIcon" ascii //weight: 5
        $x_1_2 = "anallergic" ascii //weight: 1
        $x_1_3 = "apneustic" ascii //weight: 1
        $x_1_4 = "elytrin" ascii //weight: 1
        $x_1_5 = "homecrofting" ascii //weight: 1
        $x_1_6 = "longway" ascii //weight: 1
        $x_1_7 = "omnicorporeal" ascii //weight: 1
        $x_1_8 = "onisciform" ascii //weight: 1
        $x_1_9 = "priscan" ascii //weight: 1
        $x_1_10 = "pyrenopeziza" ascii //weight: 1
        $x_1_11 = "unwakened" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DD_2147797397_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DD!MTB"
        threat_id = "2147797397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 1c 83 44 24 10 04 05 64 b2 00 01 a3 ?? ?? ?? ?? 89 06 8d 04 0a 8b 0d ?? ?? ?? ?? 03 c7 8b 35 ?? ?? ?? ?? 81 c1 8f 27 01 00 8d 04 42 03 c8 ff 4c 24 14}  //weight: 1, accuracy: Low
        $x_1_2 = {0f af cf 89 3d ?? ?? ?? ?? 69 f9 bc 6a 00 00 0f b6 cb 81 c6 f8 39 0b 01 8a 1d ?? ?? ?? ?? 66 2b c8 66 2b ca 89 35 ?? ?? ?? ?? 0f b7 d1 8b 4c 24 10 89 54 24 0c 89 31}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 55 fc a1 ?? ?? ?? ?? 8d 4c 02 a9 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 d8 1f 0b 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 f8 8b 0d ?? ?? ?? ?? 89 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qakbot_DD_2147797397_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DD!MTB"
        threat_id = "2147797397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jd_read_mobj" ascii //weight: 1
        $x_1_2 = "jd_read_mpls" ascii //weight: 1
        $x_1_3 = "jd_read_skip_still" ascii //weight: 1
        $x_1_4 = "jd_register_argb_overlay_proc" ascii //weight: 1
        $x_1_5 = "jd_register_overlay_proc" ascii //weight: 1
        $x_1_6 = "jd_seamless_angle_change" ascii //weight: 1
        $x_1_7 = "jd_set_player_setting_str" ascii //weight: 1
        $x_1_8 = "jd_start_bdj" ascii //weight: 1
        $x_1_9 = "jd_tell_time" ascii //weight: 1
        $x_1_10 = "menu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DE_2147797483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DE!MTB"
        threat_id = "2147797483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c0 3b c2 ?? ?? 2a 5c 24 0c 8b 06 2b 4c 24 14 05 94 d4 08 01 03 cf 89 06 a3 ?? ?? ?? ?? 83 c6 04 8a c1 89 0d ?? ?? ?? ?? 2a 44 24 0c 04 6f 83 6c 24 10 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DE_2147797483_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DE!MTB"
        threat_id = "2147797483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "LoadKeyboardLayoutA" ascii //weight: 3
        $x_3_2 = "OpenClipboard" ascii //weight: 3
        $x_3_3 = "lktgWecrXyTzWciiF" ascii //weight: 3
        $x_3_4 = "itwiecvqer" ascii //weight: 3
        $x_3_5 = "pV_wdJCShNGO" ascii //weight: 3
        $x_3_6 = "traynotify" ascii //weight: 3
        $x_3_7 = "ClientToScreen" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DE_2147797483_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DE!MTB"
        threat_id = "2147797483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kua_pushlightuserdata" ascii //weight: 1
        $x_1_2 = "kua_newuserdata" ascii //weight: 1
        $x_1_3 = "kua_gethookmask" ascii //weight: 1
        $x_1_4 = "kua_pushvfstring" ascii //weight: 1
        $x_1_5 = "must" ascii //weight: 1
        $x_1_6 = "kuaL_addstring" ascii //weight: 1
        $x_1_7 = "kuaL_buffinit" ascii //weight: 1
        $x_1_8 = "kuaL_getmetafield" ascii //weight: 1
        $x_1_9 = "kuaL_prepbuffer" ascii //weight: 1
        $x_1_10 = "kuaL_register" ascii //weight: 1
        $x_1_11 = "kua_checkstack" ascii //weight: 1
        $x_1_12 = "klc_entry_copyright__3_0_0f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DF_2147797503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DF!MTB"
        threat_id = "2147797503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 ca 2b 0d ?? ?? ?? ?? 81 c1 5c 45 01 00 0f b6 d2 89 0d ?? ?? ?? ?? 0f b6 cb 0f af d1 02 54 24 10 89 54 24 14 88 15 ?? ?? ?? ?? 8d 56 ff 8b 74 24 18 8b 0e 81 c1 70 36 08 01 89 0e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DF_2147797503_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DF!MTB"
        threat_id = "2147797503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 02 8b 45 c4 03 45 a4 89 45 a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02 8b 45 d8 83 c0 04 89 45 d8 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 a8 3b 45 cc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_RF_2147797666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RF!MTB"
        threat_id = "2147797666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 02 6a 00 e8 ?? ?? ?? ?? 83 c0 04 01 05 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 29 05 ?? ?? ?? ?? 83 05 ?? ?? ?? ?? 04}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 00 10 00 00 a3 ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_RF_2147797666_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RF!MTB"
        threat_id = "2147797666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 02 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04 [0-40] 2b d8 01 5d ?? 83 05 ?? ?? ?? ?? 04 8b 45 ?? 3b 05 ?? ?? ?? ?? 72 ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 2d 00 10 00 00 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_RM_2147797818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RM!MTB"
        threat_id = "2147797818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 18 89 05 ?? ?? ?? ?? b8 26 00 00 00 03 05 ?? ?? ?? ?? 83 e8 4f 33 05 ?? ?? ?? ?? 03 c0 81 e8 36 52 e0 7d 03 c0 83 e8 1f 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_RM_2147797818_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RM!MTB"
        threat_id = "2147797818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 98 d9 0b 01 88 54 24 ?? 8a d3 2a d1 89 07 80 c2 13 a3 ?? ?? ?? ?? 0f b7 c9 83 c7 04 0f b6 c2 0f af c1 66 03 44 24 ?? 83 6c 24 ?? 01 0f b7 c8 89 ?? 24 4c 0f b7 c8 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_RM_2147797818_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RM!MTB"
        threat_id = "2147797818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c1 38 10 00 00 8b 55 ?? 8b 02 2b c1 8b 4d ?? 89 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d2 33 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 8b d2 01 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 8b e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_RMA_2147797819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RMA!MTB"
        threat_id = "2147797819"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 70 83 07 01 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 8b 15 ?? ?? ?? ?? 89 91 ?? ?? ?? ?? a1 ?? ?? ?? ?? 6b c0 03 03 05 ?? ?? ?? ?? 66 89 45 ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EY_2147797871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EY!MTB"
        threat_id = "2147797871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b7 c2 0f b6 cb 2b c8 83 c1 b4 03 f9 8b 4c 24 0c 8b 01 05 88 7f 03 01 89 01 83 c1 04}  //weight: 10, accuracy: High
        $x_10_2 = {8a ca 02 4c 24 10 b0 f0 02 c9 2a c1 8b ce 02 d8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EY_2147797871_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EY!MTB"
        threat_id = "2147797871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 18 6a 00 e8 ?? ?? ?? ?? 8b d8 8b 45 c4 03 45 a4 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d8 33 18 89 5d a0 6a 00 e8 ?? ?? ?? ?? 8b d8 03 5d a0 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d8 89 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AD_2147797872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AD!MTB"
        threat_id = "2147797872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 cb 6b d9 35 8b 4c 24 0c 2a 5c 24 10 8b 09 89 5c 24 18 81 c1 c4 5e 02 01}  //weight: 10, accuracy: High
        $x_10_2 = {8b 5c 24 0c 83 44 24 0c 04 83 6c 24 14 01 89 0d ?? ?? ?? ?? 89 0b 8b 5c 24 18 0f b7 cf 89 4c 24 10}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AD_2147797872_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AD!MTB"
        threat_id = "2147797872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b d8 4b 6a 00 e8 [0-4] 03 d8 6a 00 e8 [0-4] 03 d8 6a 00 e8 [0-4] 03 d8 a1 [0-4] 33 18 89 1d [0-4] 6a 00 e8 [0-4] 03 05 [0-4] 8b 15 [0-4] 89 02 a1 [0-4] 83 c0 04 a3 [0-4] 33 c0 a3 [0-4] a1 [0-4] 83 c0 04 03 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AD_2147797872_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AD!MTB"
        threat_id = "2147797872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DllRegisterServer" ascii //weight: 3
        $x_3_2 = "DxaZi" ascii //weight: 3
        $x_3_3 = "EApvfpvNy" ascii //weight: 3
        $x_3_4 = "EQpvbeDR" ascii //weight: 3
        $x_3_5 = "CryptAcquireContextW" ascii //weight: 3
        $x_3_6 = "CryptReleaseContext" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AD_2147797872_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AD!MTB"
        threat_id = "2147797872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 8d 0c 16 83 e0 ?? 8a 80 ?? ?? ?? ?? 32 04 0f 46 88 01 3b f3 72 ?? 5f 5e}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 8b c3 f7 75 ?? 8b 45 ?? 8a 04 02 32 04 0b 88 04 1f 43 83 ee 01 75}  //weight: 1, accuracy: Low
        $x_1_3 = {33 d2 8b c3 f7 f6 8b 45 ?? 8a 04 02 8b 55 ?? 32 04 13 8b 55 ?? 0f b6 c0 66 89 04 51 42 43 89 55 ?? 3b d7 72}  //weight: 1, accuracy: Low
        $x_1_4 = {8b c1 83 e0 ?? 8a 84 30 ?? 32 44 0e ?? 88 04 11 41 3b 0e 72}  //weight: 1, accuracy: Low
        $x_1_5 = {8b c7 83 e0 ?? 8a 44 05 ?? 32 04 37 88 44 3b ?? 47 3b 3b 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Qakbot_RW_2147798043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RW!MTB"
        threat_id = "2147798043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d f2 05 00 00 03 05 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_RTH_2147798074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RTH!MTB"
        threat_id = "2147798074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 b8 93 29 8b 4c 24 ?? 8b 54 24 ?? 66 c7 44 24 ?? 92 a6 66 8b 74 24 ?? 6b c9 48 01 ca 89 54 24 ?? c7 84 24 ?? ?? ?? ?? a2 91 9f 8e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_RTH_2147798074_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RTH!MTB"
        threat_id = "2147798074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 03 05 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 89 18 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PAB_2147799054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PAB!MTB"
        threat_id = "2147799054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 3a c0 bb 04 00 00 00 53 3a ed 5e f7 f6 66 3b db 0f b6 44 15 ?? 33 c8 3a c0 8b 45 ?? 88 4c 05 ?? 8b 45 ?? 40 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PAB_2147799054_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PAB!MTB"
        threat_id = "2147799054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {3b fc 87 e7 5e 49 0f a4 d3 37 81 de 9a 0a 00 00 81 fa 1c 1f 00 00 c1 ee 8b f7 e6 f7 ff f7 c4 39 08 00 00 e4 b4 cd 98 69 e4 2f 03 00 00 81 d2 b5 1d 00 00 0f a4 db af}  //weight: 2, accuracy: High
        $x_1_2 = "DhWtecS52LH6g34.dll" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "FonkIkN" ascii //weight: 1
        $x_1_5 = "MqvdEvZv" ascii //weight: 1
        $x_1_6 = "VBFjHxFOxC" ascii //weight: 1
        $x_1_7 = "clExrVqR" ascii //weight: 1
        $x_1_8 = "kMUak" ascii //weight: 1
        $x_1_9 = "krBVEuWjdl" ascii //weight: 1
        $x_1_10 = "tgWzBT" ascii //weight: 1
        $x_1_11 = "twHIs" ascii //weight: 1
        $x_1_12 = "vaobCj" ascii //weight: 1
        $x_1_13 = "yMBeGI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PAC_2147805368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PAC!MTB"
        threat_id = "2147805368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IUID_PROCESSOR_IDLE_DISABLE" ascii //weight: 1
        $x_1_2 = "IUID_DISK_BURST_IGNORE_THRESHOLD" ascii //weight: 1
        $x_1_3 = "IUID_PROCESSOR_PARKING_HEADROOM_THRESHOLD" ascii //weight: 1
        $x_1_4 = "IID_IBindStatusCallbackEx" ascii //weight: 1
        $x_1_5 = "IFXVideoUSER_UnLoad" ascii //weight: 1
        $x_1_6 = "IZN3MFX11DXVA2DeviceC2Ev" ascii //weight: 1
        $x_1_7 = "Motd" ascii //weight: 1
        $x_1_8 = "IZTVN3MFX9MFXVectorIP15MFX_DISP_HANDLEEE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PAC_2147805368_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PAC!MTB"
        threat_id = "2147805368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {85 c4 e4 fe 81 d1 fc 04 00 00 81 ea 0d 13 00 00 69 ed 96 23 00 00 13 e8 e4 e5 03 f5 ff d7 cd 87 42 87 d4 81 d2 9b 06 00 00 4f 0b d7 50 0f a4 fb}  //weight: 2, accuracy: High
        $x_1_2 = "aMhZi0AVye.dll" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "EofYkuy" ascii //weight: 1
        $x_1_5 = "JlMycqC" ascii //weight: 1
        $x_1_6 = "MchtuL" ascii //weight: 1
        $x_1_7 = "PeidHgjWi" ascii //weight: 1
        $x_1_8 = "UyKXRTTMeS" ascii //weight: 1
        $x_1_9 = "WURXGav" ascii //weight: 1
        $x_1_10 = "XgTdDZoq" ascii //weight: 1
        $x_1_11 = "YbvxbDP" ascii //weight: 1
        $x_1_12 = "ceksjUYZ" ascii //weight: 1
        $x_1_13 = "cidTwcyr" ascii //weight: 1
        $x_1_14 = "fGFODZzHP" ascii //weight: 1
        $x_1_15 = "iPUeBvdi" ascii //weight: 1
        $x_1_16 = "iUgbioCE" ascii //weight: 1
        $x_1_17 = "jAGEO" ascii //weight: 1
        $x_1_18 = "qakvr" ascii //weight: 1
        $x_1_19 = "xVjrAwSs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_CE_2147806405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.CE!MTB"
        threat_id = "2147806405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "LoadKeyboardLayoutA" ascii //weight: 3
        $x_3_2 = "MessageBeep" ascii //weight: 3
        $x_3_3 = "mAcyvi5x" ascii //weight: 3
        $x_3_4 = "CJwve9y" ascii //weight: 3
        $x_3_5 = "BGgfLDN_KX_UI" ascii //weight: 3
        $x_3_6 = "traynotify" ascii //weight: 3
        $x_3_7 = "ClientToScreen" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_CE_2147806405_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.CE!MTB"
        threat_id = "2147806405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RP8LCheckSignature" ascii //weight: 1
        $x_1_2 = "RebPBlendAlpha" ascii //weight: 1
        $x_1_3 = "RebPCleanupTransparentArea" ascii //weight: 1
        $x_1_4 = "RebPConfigInitInternal" ascii //weight: 1
        $x_1_5 = "RebPDecodeARGBInto" ascii //weight: 1
        $x_1_6 = "RebPDecodeYUVInto" ascii //weight: 1
        $x_1_7 = "RebPEncodeLosslessBGR" ascii //weight: 1
        $x_1_8 = "RebPGetDecoderVersion" ascii //weight: 1
        $x_1_9 = "RebPInitDecoderConfigInternal" ascii //weight: 1
        $x_1_10 = "RebPPictureARGBToYUVADithered" ascii //weight: 1
        $x_1_11 = "RebPMemoryWriterInit" ascii //weight: 1
        $x_1_12 = "RebPPictureYUVAToARGB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_QE_2147807483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.QE!MTB"
        threat_id = "2147807483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "CallNextHookEx" ascii //weight: 3
        $x_3_2 = "GetFileVersionInfoSizeA" ascii //weight: 3
        $x_3_3 = "LockResource" ascii //weight: 3
        $x_3_4 = "SysReAllocStringLen" ascii //weight: 3
        $x_3_5 = "ActivateKeyboardLayout" ascii //weight: 3
        $x_3_6 = "WinSpool" ascii //weight: 3
        $x_3_7 = "CLleWKir@REu@gaBMgm" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DG_2147807899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DG!MTB"
        threat_id = "2147807899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 e8}  //weight: 1, accuracy: High
        $x_1_2 = {8b d8 8b 45 d8 83 c0 04 03 45 a4 03 d8 e8 [0-4] 2b d8 e8 [0-4] 2b d8 e8 [0-4] 03 d8 89 5d d8 8b 45 a8 3b 45 cc 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DG_2147807899_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DG!MTB"
        threat_id = "2147807899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mutant Gene Software" ascii //weight: 1
        $x_1_2 = "Pocket Radio Player" ascii //weight: 1
        $x_1_3 = "Too many hook ids" ascii //weight: 1
        $x_1_4 = "stager_1.dll" ascii //weight: 1
        $x_1_5 = "DllRegisterServer" ascii //weight: 1
        $x_1_6 = "gethostbyname" ascii //weight: 1
        $x_1_7 = "GetClipboardData" ascii //weight: 1
        $x_1_8 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_9 = "GetKeyState" ascii //weight: 1
        $x_1_10 = "MinGW-W64 i686-posix-dwarf" ascii //weight: 1
        $x_1_11 = "inflate" ascii //weight: 1
        $x_1_12 = "deflate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_RT_2147808755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RT!MTB"
        threat_id = "2147808755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1d 45 12 eb 06 1a 41 ?? 33 04 5f 03 db 4b 03 d2 81 e8 e8 ef 00 00 33 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_RT_2147808755_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RT!MTB"
        threat_id = "2147808755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 69 c8 af d7 8b 94 24 ?? ?? ?? ?? 81 c2 f2 29 a5 87 66 89 8c 24 ?? ?? ?? ?? 39 [0-4] 72}  //weight: 1, accuracy: Low
        $x_1_2 = {81 e1 8e 46 1b 50 89 8c 24 ?? ?? ?? ?? 8b 44 c2 ?? 89 44 24 ?? 66 8b 74 24 ?? 66 89 b4 24 ?? ?? ?? ?? 8b 44 24 ?? c7 84 24 ?? ?? ?? ?? f8 19 ab 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_RT_2147808755_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RT!MTB"
        threat_id = "2147808755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {4b 03 da 03 f8 33 fe 89 95 34 f0 ff ff 2b fb 33 cf fe c1 81 ff 3b 16 00 00 75}  //weight: 10, accuracy: High
        $x_1_2 = "BugreportFeaturerequestKnownIssues1" ascii //weight: 1
        $x_1_3 = "username_txt" ascii //weight: 1
        $x_1_4 = "password_txt" ascii //weight: 1
        $x_1_5 = "LookupAccountSidW" ascii //weight: 1
        $x_1_6 = "stager_1.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_ZY_2147811522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.ZY"
        threat_id = "2147811522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {80 ea 80 88 55 f0 e8 ?? ?? ?? ?? 0f b6 4d [0-3] 0f b6 45 [0-3] 0f b6 4d [0-3] 0f b6 4d [0-3] 0f b6 4d [0-3] 0f b6 45 [0-3] 0f b6 45 [0-3] 0f b6 45 [0-3] 0f b6 45 [0-3] 0f b6 45 [0-3] 0f b6 45 [0-3] 0f b6 45 [0-3] 0f b6 45 [0-3] 0f b6 45 [0-3] 0f b6 45 [0-3] 0f b6 45 ?? ?? ?? 6a 28 ?? 89 55 fc e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_ZW_2147811524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.ZW"
        threat_id = "2147811524"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_5_2 = {0f af 81 44 06 00 00}  //weight: 5, accuracy: High
        $x_5_3 = {f6 80 98 18 00 00 82}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_ZV_2147811525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.ZV"
        threat_id = "2147811525"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_5_2 = {d0 07 00 00}  //weight: 5, accuracy: High
        $x_5_3 = {a0 0f 00 00 02 00 81}  //weight: 5, accuracy: Low
        $x_5_4 = {d0 07 00 00 02 00 81}  //weight: 5, accuracy: Low
        $x_5_5 = {70 17 00 00 02 00 81}  //weight: 5, accuracy: Low
        $x_5_6 = {f7 04 84 ff 04 00 c7 45 ?? 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DF_2147812358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DF"
        threat_id = "2147812358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "esentutl" wide //weight: 10
        $x_10_2 = "V01" wide //weight: 10
        $x_10_3 = " /r" wide //weight: 10
        $x_1_4 = " /l" wide //weight: 1
        $x_1_5 = " /s" wide //weight: 1
        $x_1_6 = " /d" wide //weight: 1
        $x_10_7 = "AppData\\Local\\Microsoft\\Windows\\WebCache" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_DC_2147812359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DC"
        threat_id = "2147812359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "rmdir" wide //weight: 10
        $x_10_2 = "EmailStorage" wide //weight: 10
        $x_10_3 = " /Q " wide //weight: 10
        $x_10_4 = " /S " wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PE_2147813628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PE!MTB"
        threat_id = "2147813628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d1 89 55 ?? 0f b6 05 ?? ?? ?? ?? 33 45 ?? 89 45 ?? 0f b6 0d ?? ?? ?? ?? 8b 55 ?? 2b d1 89 55 ?? 0f b6 05 ?? ?? ?? ?? 03 45 ?? 89 45 ?? 0f b6 0d ?? ?? ?? ?? 8b 55 ?? 2b d1 89 55 ?? a1 00 10 00 10 03 45 ?? 8a 4d ?? 88 08 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {2b d1 89 55 ?? 0f b6 05 ?? ?? ?? ?? 33 45 ?? 89 45 ?? 0f b6 0d ?? ?? ?? ?? 33 4d ?? 89 4d ?? 0f b6 15 ?? ?? ?? ?? 8b 45 ?? 2b c2 89 45 ?? 0f b6 0d ?? ?? ?? ?? 8b 55 ?? 2b d1 89 55 ?? a1 00 70 0c 10 03 45 ?? 8a 4d ?? 88 08 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qakbot_PF_2147813630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PF!MTB"
        threat_id = "2147813630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d a2 d1 00 00 03 05 [0-4] a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 01 [0-208] 6a 01 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AC_2147813763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AC!MTB"
        threat_id = "2147813763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "AFvSru" ascii //weight: 3
        $x_3_2 = "DllRegisterServer" ascii //weight: 3
        $x_3_3 = "EKVmtn" ascii //weight: 3
        $x_3_4 = "ExxXbjuo" ascii //weight: 3
        $x_3_5 = "StrRetToStrA" ascii //weight: 3
        $x_3_6 = "StrRetToBufW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AC_2147813763_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AC!MTB"
        threat_id = "2147813763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b d8 4b 6a 00 e8 [0-4] 03 d8 6a 00 e8 [0-4] 03 d8 a1 [0-4] 33 18 89 1d [0-4] 6a 00 e8 [0-4] 03 05 [0-4] 8b 15 [0-4] 89 02 a1 [0-4] 83 c0 04 a3 [0-4] 33 c0 a3 [0-4] a1 [0-4] 83 c0 04 03 05 [0-4] a3 [0-4] a1 [0-4] 3b 05 [0-4] 0f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AC_2147813763_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AC!MTB"
        threat_id = "2147813763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 3a c0 74 ?? 83 f8 46 7e ?? 83 65 fc 00 eb ?? 3a ed 74 ?? 83 f8 41 7c ?? 0f be 45 08 eb ?? c3}  //weight: 1, accuracy: Low
        $x_1_2 = {51 0f be 45 ?? 66 3b e4 74 ?? 83 f8 30 7c ?? 0f be 45 ?? 66 3b c0 74 ?? 83 f8 66 7e ?? 0f be 45 ?? eb ?? 83 f8 61 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AH_2147813960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AH!MTB"
        threat_id = "2147813960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 b5 16 80 45 b5 56 66 3b ed 74}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 b4 3a 80 45 b4 0a e9}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 c2 54 80 45 c2 22 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AH_2147813960_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AH!MTB"
        threat_id = "2147813960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {47 8d 0c 86 0f b7 c5 0f af 44 24 28 66 45 09 01 8b 44 24 14 8b 4c 24 20 31 44 24 1c 41 81 22 8d 1c 00 00 0f b7 c3 89 4c 24 20 3b c8 74}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EM_2147814046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EM!MTB"
        threat_id = "2147814046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f4 0f b6 4c 05}  //weight: 1, accuracy: High
        $x_1_2 = {f7 f6 0f b6 44 15}  //weight: 1, accuracy: High
        $x_1_3 = {33 c8 8b 45}  //weight: 1, accuracy: High
        $x_1_4 = {88 4c 05 a4 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EM_2147814046_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EM!MTB"
        threat_id = "2147814046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8b cb 83 c6 04 0b cf 0b 4c 24 30 0b d1 8b cd 89 90 a8 00 00 00 2b 48 0c 69 c9 4c 03 00 00 3b f1 72 de}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EM_2147814046_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EM!MTB"
        threat_id = "2147814046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 33 18 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 10}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EM_2147814046_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EM!MTB"
        threat_id = "2147814046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 83 ec 08 89 4d fc 8b 45 fc 89 45 f8 6b 45 08 18 8b 4d f8 03 01 8b e5 5d}  //weight: 5, accuracy: High
        $x_1_2 = "desktop.d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EM_2147814046_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EM!MTB"
        threat_id = "2147814046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "jPUMOOUiE.dll" ascii //weight: 1
        $x_1_3 = "AmXX6i1Wxh" ascii //weight: 1
        $x_1_4 = "D3g4gCh2" ascii //weight: 1
        $x_1_5 = "JkDpzDORVU" ascii //weight: 1
        $x_1_6 = "CSNZ4z" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EM_2147814046_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EM!MTB"
        threat_id = "2147814046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ZHxbETopuOI" ascii //weight: 3
        $x_3_2 = "gUmamXP" ascii //weight: 3
        $x_3_3 = "jKuEkhbMkMhYKG" ascii //weight: 3
        $x_3_4 = "ScriptCPtoX" ascii //weight: 3
        $x_3_5 = "ScriptApplyLogicalWidth" ascii //weight: 3
        $x_3_6 = "CloseEnhMetaFile" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AE_2147814224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AE!MTB"
        threat_id = "2147814224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d a2 d1 00 00 03 05 [0-4] a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 01 [0-208] 6a 01 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AE_2147814224_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AE!MTB"
        threat_id = "2147814224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b d8 4b 6a 00 e8 [0-4] 03 d8 6a 00 e8 [0-4] 03 d8 6a 00 e8 [0-4] 03 d8 6a 00 e8 [0-4] 03 d8 a1 [0-4] 33 18 89 1d [0-4] 6a 00 e8 [0-4] 8b d8 03 1d [0-4] 6a 00 e8 [0-4] 03 d8 a1 [0-4] 89 18 a1 [0-4] 83 c0 04 a3 [0-4] 33 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DH_2147814540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DH!MTB"
        threat_id = "2147814540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "74aWCPaj.dll" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "RaiseException" ascii //weight: 1
        $x_1_6 = "CreateFileW" ascii //weight: 1
        $x_1_7 = "WriteConsoleW" ascii //weight: 1
        $x_1_8 = "ci0P162BNwYao26sfbd5bkX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AI_2147814557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AI!MTB"
        threat_id = "2147814557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2f0ab2717af9bfe0" ascii //weight: 1
        $x_1_2 = "3a6f7dc06b7c1bf1" ascii //weight: 1
        $x_1_3 = "53cd7e7469c332c0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AI_2147814557_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AI!MTB"
        threat_id = "2147814557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {69 66 3b e4 74 ?? c6 45 ?? 72 66 3b db 74 ?? c6 45 ?? 65 66 3b ed 74 ?? c6 45 ?? 53 66 3b f6 74 ?? c6 45 ?? 76 eb ?? c6 45 ?? 72 66 3b d2 74 ?? c6 45 ?? 73 3a e4 74 ?? c6 45 ?? 65 3a d2 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DJ_2147814582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DJ!MTB"
        threat_id = "2147814582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "out.dll" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "DllUnregisterServer" ascii //weight: 1
        $x_1_4 = "anonymously" ascii //weight: 1
        $x_1_5 = "devitalization" ascii //weight: 1
        $x_1_6 = "interlinguistic" ascii //weight: 1
        $x_1_7 = "philathletic" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DK_2147814632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DK!MTB"
        threat_id = "2147814632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 80 0d 00 00 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 83 c0 04 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DK_2147814632_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DK!MTB"
        threat_id = "2147814632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "out.dll" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "DllUnregisterServer" ascii //weight: 1
        $x_1_4 = "anomoeanism" ascii //weight: 1
        $x_1_5 = "choreographical" ascii //weight: 1
        $x_1_6 = "apodictically" ascii //weight: 1
        $x_1_7 = "galvanothermometer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DK_2147814632_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DK!MTB"
        threat_id = "2147814632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kIO_new_ssl_connect" ascii //weight: 1
        $x_1_2 = "kIO_new_buffer_ssl_connect" ascii //weight: 1
        $x_1_3 = "kIO_ssl_shutdown" ascii //weight: 1
        $x_1_4 = "kEM_read_bio_SSL_SESSION" ascii //weight: 1
        $x_1_5 = "kSL_COMP_add_compression_method" ascii //weight: 1
        $x_1_6 = "kSL_CTX_check_private_key" ascii //weight: 1
        $x_1_7 = "kSL_CTX_get_quiet_shutdown" ascii //weight: 1
        $x_1_8 = "kSL_CONF_CTX_set1_prefix" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AK_2147814643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AK!MTB"
        threat_id = "2147814643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 45 a8 03 45 ac 48 89 45 a4 8b 45 a8 8b 55 d8 01 02}  //weight: 3, accuracy: High
        $x_3_2 = {8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AK_2147814643_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AK!MTB"
        threat_id = "2147814643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "gyrthy345t345t24rt4trgywerfadjfoiouahufhasu" ascii //weight: 3
        $x_3_2 = {eb c0 7c 50 be ca 6b 41 c8 c1 7a 65 bf d6 08 00 ac a5 08 56}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AK_2147814643_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AK!MTB"
        threat_id = "2147814643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b c8 89 4d ?? 0f b6 15 ?? ?? ?? ?? 33 55 ?? 89 55 ?? 0f b6 05 ?? ?? ?? ?? 8b 4d ?? 2b c8 89 4d ?? 0f b6 15 ?? ?? ?? ?? 33 55 ?? 89 55 ?? a1 ?? ?? ?? ?? 03 45 ?? 8a 4d ?? 88 08 e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GW_2147814679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GW!MTB"
        threat_id = "2147814679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 18 89 1d [0-60] 03 d8 a1 ?? ?? ?? ?? 89 18 a1 ?? ?? ?? ?? 83 c0 04 a3 ?? ?? ?? ?? 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DI_2147814730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DI!MTB"
        threat_id = "2147814730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 80 0d 00 00 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 83 c0 04 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 99 52 50 a1 ?? ?? ?? ?? 33 d2 3b 54 24 04 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AJ_2147814742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AJ!MTB"
        threat_id = "2147814742"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 45 e0 89 45 dc 8b 45 f0 03 45 e0 89 45 f0 8b 45 ec 2b 45 e0 89 45 ec 83 7d e0 00 76 50 00 ff 75 ?? ff 75 ?? 8b 45 ?? 8b 40 ?? 8b 4d ?? 8b 00 8b 49 ?? ff 50 ?? 89 45 ?? 8b 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AJ_2147814742_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AJ!MTB"
        threat_id = "2147814742"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {69 66 3b db 74 ?? c6 45 ?? 65 66 3b ?? 74 ?? c6 45 ?? 73 66 3b ?? 74 ?? c6 45 ?? 74 3a ?? 74 ?? c6 45 ?? 52 66 3b ?? 74 ?? c6 45 ?? 67 66 3b ?? 74 ?? c6 45 ?? 65 66 3b ?? 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_NB_2147814902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.NB!MTB"
        threat_id = "2147814902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "HdBNO8I7g4G.dll" ascii //weight: 3
        $x_3_2 = "DllRegisterServer" ascii //weight: 3
        $x_3_3 = "DtmquRoDk" ascii //weight: 3
        $x_3_4 = "wOtnr" ascii //weight: 3
        $x_3_5 = "yJtuHEtei" ascii //weight: 3
        $x_3_6 = "MlvBprcPeIUENXHAahL8hrf9FyT7ecVzD67kju6IM6DnBLB26ocO1ZxRrzhj" ascii //weight: 3
        $x_3_7 = "ScriptGetGlyphABCWidth" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_NC_2147814903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.NC!MTB"
        threat_id = "2147814903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "xercesxmldom.dll" ascii //weight: 3
        $x_3_2 = "WSDLPub" ascii //weight: 3
        $x_3_3 = "InquireSoap" ascii //weight: 3
        $x_3_4 = "inquire_v1" ascii //weight: 3
        $x_3_5 = "GetLongPathNameA" ascii //weight: 3
        $x_3_6 = "ioctlsocket" ascii //weight: 3
        $x_3_7 = "getpeername" ascii //weight: 3
        $x_3_8 = "getsockname" ascii //weight: 3
        $x_3_9 = "gethostbyname" ascii //weight: 3
        $x_3_10 = "shutdown" ascii //weight: 3
        $x_3_11 = "j8hyubtnvejrtgeorhwry" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DL_2147814996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DL!MTB"
        threat_id = "2147814996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 80 0d 00 00 03 45 ?? 89 45 ?? 8b 45 ?? 03 45 ?? 8b 55 ?? 31 02 6a 00 e8 ?? ?? ?? ?? 8b d8 8b 45 9c 83 c0 04 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DL_2147814996_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DL!MTB"
        threat_id = "2147814996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "k?0?$CacheKey@VDateFmtBestPattern@icu_57@@@icu_57@@QAE@ABV01@@Z" ascii //weight: 1
        $x_1_2 = "k?0CurrencyPluralInfo@icu_57@@QAE@ABV01@@Z" ascii //weight: 1
        $x_1_3 = "k?0CollationWeights@icu_57@@QAE@XZ" ascii //weight: 1
        $x_1_4 = "k?0?$PluralMap@VDigitAffix@icu_57@@@icu_57@@QAE@XZ" ascii //weight: 1
        $x_1_5 = "more" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DM_2147815095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DM!MTB"
        threat_id = "2147815095"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 80 0d 00 00 03 45 ?? 89 45 ?? 8b 45 ?? 03 45 ?? 8b 55 ?? 31 02 e8 ?? ?? ?? ?? 8b d8 8b 45 ?? 83 c0 ?? 03 d8 e8 ?? ?? ?? ?? 2b d8 e8 ?? ?? ?? ?? 03 d8 e8 ?? ?? ?? ?? 2b d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_CB_2147815193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.CB!MTB"
        threat_id = "2147815193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 d9 56 29 cb 8b 46 08 03 46 10 01 4e 10 89 c6 89 ca c1 e9 02 fc}  //weight: 10, accuracy: High
        $x_1_2 = "Tdrhymw4oi5j" ascii //weight: 1
        $x_1_3 = "55666n0jumb4956j8hyubtnvejrtgeorhwry958u6j9y5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_CB_2147815193_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.CB!MTB"
        threat_id = "2147815193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HJBUFSIZEYUV" ascii //weight: 1
        $x_1_2 = "Hcopy_markers_execute" ascii //weight: 1
        $x_1_3 = "Hinit_1pass_quantizer" ascii //weight: 1
        $x_1_4 = "Hpeg_CreateDecompress" ascii //weight: 1
        $x_1_5 = "Hpeg_huff_decode" ascii //weight: 1
        $x_1_6 = "Hpeg_make_c_derived_tbl" ascii //weight: 1
        $x_1_7 = "Hsimd_can_convsamp_float" ascii //weight: 1
        $x_1_8 = "Hsimd_can_h2v2_fancy_upsample" ascii //weight: 1
        $x_1_9 = "HjDecompressToYUV" ascii //weight: 1
        $x_1_10 = "Hpeg_open_backing_store" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DN_2147815427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DN!MTB"
        threat_id = "2147815427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "qj32wg7lHDS.dll" ascii //weight: 1
        $x_1_3 = "FrsBZDCmK" ascii //weight: 1
        $x_1_4 = "SBnPMWIm" ascii //weight: 1
        $x_1_5 = "TSLxfJq" ascii //weight: 1
        $x_1_6 = "nzgCQGRLDC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DN_2147815427_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DN!MTB"
        threat_id = "2147815427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "k?0Appendable@icu_51@@QAE@ABV01@@Z" ascii //weight: 1
        $x_1_2 = "k?0ByteSink@icu_51@@QAE@XZ" ascii //weight: 1
        $x_1_3 = "k?0Hashtable@icu_51@@QAE@AAW4UErrorCode@@@Z" ascii //weight: 1
        $x_1_4 = "k?0IDNAInfo@icu_51@@QAE@XZ" ascii //weight: 1
        $x_1_5 = "k?0Mutex@icu_51@@QAE@PAUUMutex@@@Z" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_RTC_2147815446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RTC!MTB"
        threat_id = "2147815446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? bb 00 00 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 83 05 ?? ?? ?? ?? 04 81 2d ?? ?? ?? ?? 00 10 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DO_2147815477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DO!MTB"
        threat_id = "2147815477"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "nds30wR.dll" ascii //weight: 1
        $x_1_3 = "LAlwLWIquo" ascii //weight: 1
        $x_1_4 = "RAdtVKhANp" ascii //weight: 1
        $x_1_5 = "XkFSNNmpx" ascii //weight: 1
        $x_1_6 = "ZMEpBDXWkP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DO_2147815477_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DO!MTB"
        threat_id = "2147815477"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "k_app_info_create_from_commandline" ascii //weight: 2
        $x_2_2 = "k_app_info_can_remove_supports_type" ascii //weight: 2
        $x_2_3 = "k_action_map_add_action_entries" ascii //weight: 2
        $x_2_4 = "k_app_info_get_default_for_uri_scheme" ascii //weight: 2
        $x_2_5 = "k_application_command_line_get_cwd" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DP_2147815518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DP!MTB"
        threat_id = "2147815518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 9c 8b 55 d8 01 02 8b 45 b4 83 e8 2c 03 45 9c 89 45 b0 8b 45 cc 03 45 b0 8b 55 d8 31 02 83 45 9c 04 8b 45 d8 83 c0 04 89 45 d8 8b 45 9c 99 52 50 8b 45 d4 33 d2 3b 54 24 04 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DP_2147815518_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DP!MTB"
        threat_id = "2147815518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RZ13listToVariantI12KAboutPersonE5QListI8QVariantERKS1_IT_E" ascii //weight: 2
        $x_2_2 = "RZ19staleMatchesManagedRK7QStringRK4QUrl" ascii //weight: 2
        $x_2_3 = "RZ5qHashRK7KUserIdj" ascii //weight: 2
        $x_2_4 = "RZN10KAboutData18fromPluginMetaDataERK15KPluginMetaData" ascii //weight: 2
        $x_2_5 = "RZN10KUserGroupC1EN5KUser7UIDModeE" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MP_2147815563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MP!MTB"
        threat_id = "2147815563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 fc 83 c2 01 89 55 fc 83 7d fc 12 73 28 8b 45 fc 6b c0 13 03 45 f8 50 8b 4d d0 51 8b 55 08 8b 82 44 03 00 00 ff d0 8b 4d fc 8b 55 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MPE_2147815564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MPE!MTB"
        threat_id = "2147815564"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e0 8b 00 89 45 d4 8b 45 e0 83 c0 04 89 45 e0 8b 45 d8 89 45 dc 8b 45 dc 83 e8 04 89 45 dc 33 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DQ_2147815760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DQ!MTB"
        threat_id = "2147815760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "SlueV.dll" ascii //weight: 1
        $x_1_3 = "ExxXbjuo" ascii //weight: 1
        $x_1_4 = "NsgzacToa" ascii //weight: 1
        $x_1_5 = "YiLyshoKpj" ascii //weight: 1
        $x_1_6 = "ddzIzUrvft" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DR_2147815821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DR!MTB"
        threat_id = "2147815821"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "r.dll" ascii //weight: 1
        $x_1_3 = "CPOqiyLM8T" ascii //weight: 1
        $x_1_4 = "CTuPAKPKOPX" ascii //weight: 1
        $x_1_5 = "CzFzJgZAzJ8" ascii //weight: 1
        $x_1_6 = "D7FN3uDF7sl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PAN_2147815861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PAN!MTB"
        threat_id = "2147815861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 cf 81 f9 ?? ?? ?? ?? 81 d7 23 19 00 00 81 d3 0c 05 00 00 bc ef 14 00 00 c8 f0 00 00 03 ec 25 ?? ?? ?? ?? f7 d6 85 df e6 2c 81 db 66 13 00 00 5e}  //weight: 1, accuracy: Low
        $x_1_2 = {51 51 3a ed 74 14 33 c0 40 eb 0b 8b 45 0c 89 45 f8 66 3b c0 74 f0 c9 c2 0c 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 66 3b db 74 ce 55 8b ec 66 3b f6 74 cf 81 f9 fb 15 00 00 81 d7 23 19 00 00 81 d3 0c}  //weight: 1, accuracy: Low
        $x_1_3 = {f7 d0 0f 57 c0 66 0f 13 45 f8 eb ba 89 4d fc 8b 45 08 3a e4 74 26 55 8b ec 3a f6 74 00 51 51 66 3b ed 74 de 83 c0 01 8b 4d fc 66 3b d2 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qakbot_AM_2147815958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AM!MTB"
        threat_id = "2147815958"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Co3jCnSaq" ascii //weight: 2
        $x_2_2 = "DllRegisterServer" ascii //weight: 2
        $x_2_3 = "EMbvFZMidd" ascii //weight: 2
        $x_2_4 = "EQ4ePb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AM_2147815958_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AM!MTB"
        threat_id = "2147815958"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bhy8.dll" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "AddFontResourceW" ascii //weight: 1
        $x_1_4 = "CreateDIBPatternBrushPt" ascii //weight: 1
        $x_1_5 = "GetCharABCWidthsA" ascii //weight: 1
        $x_1_6 = "GetGlyphOutlineA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PH_2147816005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PH!MTB"
        threat_id = "2147816005"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 66 3b c0 74 ?? 80 45 ?? 46 e9 ?? ?? ?? ?? c6 45 ?? 1f eb ?? c6 45 ?? 40 80 45 ?? 12 3a f6 74 ?? c6 45 ?? 4c 80 45 ?? 20 66 3b e4 74 ?? c6 45 ?? 24 80 45 ?? 20 3a f6 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AO_2147816179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AO!MTB"
        threat_id = "2147816179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b d8 4b 6a 00 e8 [0-4] 03 d8 6a 00 e8 [0-4] 03 d8 6a 00 e8 [0-4] 03 d8 6a 00 e8 [0-4] 03 d8 a1 [0-4] 33 18 89 1d [0-4] 6a 00 e8 [0-4] 8b d8 03 1d [0-4] 6a 00 e8 [0-4] 03 d8 6a 00 e8 [0-4] 03 d8 6a 00 e8 [0-4] 03 d8 a1 [0-4] 89 18 a1 [0-4] 83 c0 04 a3 [0-4] 33 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AO_2147816179_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AO!MTB"
        threat_id = "2147816179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 41 cd 05 ee (3a|66 3b) ?? e8 ?? ?? ?? ?? 59 (3a|66 3b) ?? 89 45 ?? 68 45 1b 13 42 (3a|66 3b) ?? e8 ?? ?? ?? ?? 59 (3a|66 3b) ?? 89 45 ?? 68 43 ac 95 0e (3a|66 3b)}  //weight: 1, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DS_2147816230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DS!MTB"
        threat_id = "2147816230"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "iEl9.dll" ascii //weight: 1
        $x_1_3 = "BwHbA6iGLpy" ascii //weight: 1
        $x_1_4 = "DAIbPS6x" ascii //weight: 1
        $x_1_5 = "DLYwBE9MP8u" ascii //weight: 1
        $x_1_6 = "DSOvfSoiT" ascii //weight: 1
        $x_1_7 = "syMo.dll" ascii //weight: 1
        $x_1_8 = "C9gyTqRWB8" ascii //weight: 1
        $x_1_9 = "Cnu3PD1bv" ascii //weight: 1
        $x_1_10 = "CseavsVk6IZ" ascii //weight: 1
        $x_1_11 = "Dx2aSBsQE8y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_DT_2147816390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DT!MTB"
        threat_id = "2147816390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 02 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 83 c3 04 03 1d ?? ?? ?? ?? 2b d8 6a 00 e8 18 00 8b 15 ?? ?? ?? ?? 33 02 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DU_2147816395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DU!MTB"
        threat_id = "2147816395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "1m.dll" ascii //weight: 1
        $x_1_3 = "BataM6ohoo" ascii //weight: 1
        $x_1_4 = "DiIXpV7Vzp" ascii //weight: 1
        $x_1_5 = "DYcfCBxS" ascii //weight: 1
        $x_1_6 = "AFd9rHM1a" ascii //weight: 1
        $x_1_7 = "Kf.dll" ascii //weight: 1
        $x_1_8 = "BuPWC82qJWW" ascii //weight: 1
        $x_1_9 = "C68zNNrUao" ascii //weight: 1
        $x_1_10 = "CzJK4zjpNiU" ascii //weight: 1
        $x_1_11 = "DQOpC5sKgC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_DV_2147816538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DV!MTB"
        threat_id = "2147816538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "Ul.dll" ascii //weight: 1
        $x_1_3 = "AY2XB5jOfA" ascii //weight: 1
        $x_1_4 = "BtcwdOr01" ascii //weight: 1
        $x_1_5 = "CMdraqui" ascii //weight: 1
        $x_1_6 = "DGmXxWVPD" ascii //weight: 1
        $x_1_7 = "OJ.dll" ascii //weight: 1
        $x_1_8 = "A5PsKU8XvG" ascii //weight: 1
        $x_1_9 = "BJ9p8D5OT" ascii //weight: 1
        $x_1_10 = "CDjMK218zrW" ascii //weight: 1
        $x_1_11 = "D5VMGuG4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_DW_2147816556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DW!MTB"
        threat_id = "2147816556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 02 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 72 18 00 8b 15 ?? ?? ?? ?? 33 02 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PAE_2147816634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PAE!MTB"
        threat_id = "2147816634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 d2 8b c3 f7 75 f4 8b 45 08 8a 04 02 32 04 3b 88 04 19 43 83 ee 01}  //weight: 5, accuracy: High
        $x_5_2 = {8b 55 fc 32 04 13 0f b6 c0 66 89 04 4e 41 43 3b cf}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PAE_2147816634_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PAE!MTB"
        threat_id = "2147816634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "R?0KernTable@icu_4_0@@QAE@PBVLEFontInstance@1@PBX@Z" ascii //weight: 1
        $x_1_2 = "R?0LayoutEngine@icu_4_0@@QAE@ABV01@@Z" ascii //weight: 1
        $x_1_3 = "R?4CanonShaping@icu_4_0@@QAEAAV01@ABV01@@Z" ascii //weight: 1
        $x_1_4 = "RxUnitsToPoints@LEFontInstance@icu_4_0@@UBEMM@Z" ascii //weight: 1
        $x_1_5 = "RallocatePositions@LEGlyphStorage@icu_4_0@@QAEHAAW4LEErrorCode@@@Z" ascii //weight: 1
        $x_1_6 = "Re_getCharIndicesWithBase_4_0" ascii //weight: 1
        $x_10_7 = "Time" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DX_2147816653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DX!MTB"
        threat_id = "2147816653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 a1 ?? ?? ?? ?? 33 18 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DY_2147816728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DY!MTB"
        threat_id = "2147816728"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "v6.dll" ascii //weight: 1
        $x_1_3 = "ArM6KIebFp" ascii //weight: 1
        $x_1_4 = "BuwQ9r0PIiB" ascii //weight: 1
        $x_1_5 = "C52ctysIgYB" ascii //weight: 1
        $x_1_6 = "DxfTMAMTfE" ascii //weight: 1
        $x_1_7 = "0n.dll" ascii //weight: 1
        $x_1_8 = "AQeVkOa" ascii //weight: 1
        $x_1_9 = "C7m1xXxjF2v" ascii //weight: 1
        $x_1_10 = "Cqgt1xuoLh" ascii //weight: 1
        $x_1_11 = "DqxDV94RXMn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_DZ_2147816744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DZ!MTB"
        threat_id = "2147816744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "X4.dll" ascii //weight: 1
        $x_1_3 = "AnemJlJ9Wq" ascii //weight: 1
        $x_1_4 = "B4OhW56MsK" ascii //weight: 1
        $x_1_5 = "CK0u0u3s72z" ascii //weight: 1
        $x_1_6 = "DX5Bf16E" ascii //weight: 1
        $x_1_7 = "A5.dll" ascii //weight: 1
        $x_1_8 = "AQOlw5lSPz" ascii //weight: 1
        $x_1_9 = "BZpLFxUJx6H" ascii //weight: 1
        $x_1_10 = "CwKGnTbFe" ascii //weight: 1
        $x_1_11 = "DpjAvdDDTb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_EA_2147816804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EA!MTB"
        threat_id = "2147816804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 6c 24 4c 8b 97 c8 00 00 00 8b 87 14 01 00 00 8b 8f 0c 01 00 00 8b 04 82 31 04 8a 8b 8f 38 01 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EA_2147816804_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EA!MTB"
        threat_id = "2147816804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {33 10 89 55 a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 d8 83 c0 04 03 45 a4}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EA_2147816804_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EA!MTB"
        threat_id = "2147816804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a c8 c0 e1 02 8a c4 c0 eb 04 80 e3 03 c0 e0 04 02 d9 8a ca c0 e9 02 80 e1 0f c0 e2 06 02 55 ff 02 c8 8b 45 f0 88 4d 09 88 5d 08 88 55 0a 88 48 ff 8b 4d f8 88 58 fe}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EA_2147816804_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EA!MTB"
        threat_id = "2147816804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GDyZ" ascii //weight: 1
        $x_1_2 = "GHQvB58h2E" ascii //weight: 1
        $x_1_3 = "Mqae01id" ascii //weight: 1
        $x_1_4 = "SNifCw242OCD" ascii //weight: 1
        $x_1_5 = "LGv5I" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EA_2147816804_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EA!MTB"
        threat_id = "2147816804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {2a c1 88 44 35 ec 46 83 fe 04 7c d9 8b 45 ec 8a ec 8a 55 ee 8a c8 83 45 e0 03 8a c4 c0 e1 02 c0 ed 04 80 e5 03 c0 e0 04 02 e9}  //weight: 3, accuracy: High
        $x_1_2 = "dfxsgdfhdgfjh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EA_2147816804_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EA!MTB"
        threat_id = "2147816804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllRegisterServer" ascii //weight: 1
        $x_1_2 = "TOcSc9898M" ascii //weight: 1
        $x_1_3 = "TRoMqVC7r" ascii //weight: 1
        $x_1_4 = "UDOysR" ascii //weight: 1
        $x_1_5 = "WXbba298N" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EA_2147816804_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EA!MTB"
        threat_id = "2147816804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "6DuY.dll" ascii //weight: 1
        $x_1_3 = "A6WbycVMY" ascii //weight: 1
        $x_1_4 = "BQq7Xy1wGw" ascii //weight: 1
        $x_1_5 = "CPfIkmG" ascii //weight: 1
        $x_1_6 = "DK4eyvIxle" ascii //weight: 1
        $x_1_7 = "jN9y.dll" ascii //weight: 1
        $x_1_8 = "BmRfHcSnM9" ascii //weight: 1
        $x_1_9 = "CbSBBE0vPXY" ascii //weight: 1
        $x_1_10 = "DU6a6rCWRT8" ascii //weight: 1
        $x_1_11 = "DFptdQAdNpx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_EB_2147816908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EB!MTB"
        threat_id = "2147816908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2b 13 2b 17 8b 45 f8 8a 14 10 8b 45 08 32 14 08 8b 45 fc 88 14 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EB_2147816908_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EB!MTB"
        threat_id = "2147816908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b d8 8b 45 d8 8b 00 03 45 a8 03 d8}  //weight: 2, accuracy: High
        $x_3_2 = {03 d8 8b 45 d8 33 18 89 5d a0}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EB_2147816908_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EB!MTB"
        threat_id = "2147816908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8b 55 d8 33 02 89 45 a0 8b 45 a0 8b 55 d8 89 02 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EB_2147816908_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EB!MTB"
        threat_id = "2147816908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {8b d3 03 f8 8b 86 48 01 00 00 8b cf d3 ea 8b 4e 1c 8a 40 ?? 34 ?? 22 d0 8b 86 34 01 00 00 88 14 01}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EB_2147816908_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EB!MTB"
        threat_id = "2147816908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {89 02 6a 00 e8 ?? ?? ?? ?? 8b d8 03 1d ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 03 d8 a1 ?? ?? ?? ?? 33 18}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EB_2147816908_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EB!MTB"
        threat_id = "2147816908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXPBLG2Gy" ascii //weight: 1
        $x_1_2 = "EzMNbQL" ascii //weight: 1
        $x_1_3 = "HngWM0x" ascii //weight: 1
        $x_1_4 = "Nsr640Y" ascii //weight: 1
        $x_1_5 = "ROUO809" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EB_2147816908_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EB!MTB"
        threat_id = "2147816908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CXfP836q6" ascii //weight: 1
        $x_1_2 = "DrawThemeIcon" ascii //weight: 1
        $x_1_3 = "GrXp40" ascii //weight: 1
        $x_1_4 = "Skj92W" ascii //weight: 1
        $x_1_5 = "WIudK398" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EB_2147816908_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EB!MTB"
        threat_id = "2147816908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 02 6a 00 e8 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 03 1d ?? ?? ?? ?? 03 1d ?? ?? ?? ?? 4b 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 a1 ?? ?? ?? ?? 33 18 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EB_2147816908_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EB!MTB"
        threat_id = "2147816908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "koYLoAUlXzOnbCdKeswhJap" ascii //weight: 1
        $x_1_2 = "gZJXwYGJwDMgPlhLecpIvqp" ascii //weight: 1
        $x_1_3 = "JXSQIPGKqclhDPOJakj" ascii //weight: 1
        $x_1_4 = "HZ10KI18N_KUITv" ascii //weight: 1
        $x_1_5 = "HZ23removeAcceleratorMarkerRK7QString" ascii //weight: 1
        $x_1_6 = "HZ5KI18Nv" ascii //weight: 1
        $x_1_7 = "HZ5ki18nPKc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EC_2147817064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EC!MTB"
        threat_id = "2147817064"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a d1 8b cb 2a d3 80 c2 1b 01 1e 0f b6 c2 83 56 04 00 2b c8 81 e9 71 51 01 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EC_2147817064_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EC!MTB"
        threat_id = "2147817064"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8b c2 0f af c2 03 f0 89 b1 9c 00 00 00 8b 81 94 00 00 00 83 f0 2f 0b f8 42 89 79 24 3b 51 38 76 df}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EC_2147817064_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EC!MTB"
        threat_id = "2147817064"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {8b 82 9c 00 00 00 33 c5 33 42 30 0f af 82 d4 00 00 00 89 82 d4 00 00 00 8b 82 a8 00 00 00 83 c1 02 23 42 48}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EC_2147817064_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EC!MTB"
        threat_id = "2147817064"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {29 34 e4 01 3c e4 50 31 04 e4 58 21 45 fc 6a 00 89 2c e4 29 ed 31 c5 89 e9 5d 89 55 f4 33 55 f4 31 c2}  //weight: 3, accuracy: High
        $x_2_2 = {6a 00 89 0c e4 ff 75 fc 59 01 f9 89 4d fc 59 c1 e7 04 49 75 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EC_2147817064_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EC!MTB"
        threat_id = "2147817064"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BucKJ660" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "OeKLr9L" ascii //weight: 1
        $x_1_4 = "PIlppn35i2" ascii //weight: 1
        $x_1_5 = "WhzxqY0Jrk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EC_2147817064_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EC!MTB"
        threat_id = "2147817064"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "0z3D.dll" ascii //weight: 1
        $x_1_3 = "APYylI90" ascii //weight: 1
        $x_1_4 = "BJ9vYTIZ" ascii //weight: 1
        $x_1_5 = "C867zOSo" ascii //weight: 1
        $x_1_6 = "DkqpyEj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EC_2147817064_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EC!MTB"
        threat_id = "2147817064"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Resolving hostname" ascii //weight: 1
        $x_1_2 = "gethostbyaddr" ascii //weight: 1
        $x_1_3 = "gethostbyname" ascii //weight: 1
        $x_1_4 = "22ylku8yh049yu034hkofw42h4ryj02g940g9vrghw08" ascii //weight: 1
        $x_1_5 = "peGDtaKHxm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EC_2147817064_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EC!MTB"
        threat_id = "2147817064"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NSIkxleBPQlcQSzGMNaocZlBNDU" ascii //weight: 1
        $x_1_2 = "RjUfvmTpaesBCaEHrkakBDZChzVo" ascii //weight: 1
        $x_1_3 = "aLheQcmMuFDhqT" ascii //weight: 1
        $x_1_4 = "rrfPgJKgcqBe" ascii //weight: 1
        $x_1_5 = "FywGGkCymVqAFasfBvdHLgPATxzw" ascii //weight: 1
        $x_1_6 = "vpIMsYKcflCohCsBeNMYqRADbaH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_ED_2147817076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.ED!MTB"
        threat_id = "2147817076"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {03 d8 43 8b 45 d8 89 18 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_ED_2147817076_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.ED!MTB"
        threat_id = "2147817076"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 a1 ?? ?? ?? ?? 33 18 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_ED_2147817076_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.ED!MTB"
        threat_id = "2147817076"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DisconnectNamedPipe" ascii //weight: 1
        $x_1_2 = "OpenStorage" ascii //weight: 1
        $x_1_3 = "mnjhuiv40" ascii //weight: 1
        $x_1_4 = "18293" ascii //weight: 1
        $x_1_5 = "aeroflot" ascii //weight: 1
        $x_1_6 = "Jjischug" ascii //weight: 1
        $x_1_7 = "1.2.11" ascii //weight: 1
        $x_1_8 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EE_2147817139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EE!MTB"
        threat_id = "2147817139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 a1 ?? ?? ?? ?? 01 18 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 48 8b 15 ?? ?? ?? ?? 33 02 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EF_2147817140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EF!MTB"
        threat_id = "2147817140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 8b 45 d8 03 45 ac 03 45 e8 03 d8 e8 ?? ?? ?? ?? 2b d8 89 5d b0 8b 45 b4 33 45 b0 8b 55 ec 89 02 83 45 e8 04 8b 45 ec 83 c0 04 89 45 ec 8b 45 e8 3b 45 e4 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EG_2147817150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EG!MTB"
        threat_id = "2147817150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "fz1C.dll" ascii //weight: 1
        $x_1_3 = "ATLXiwKaC" ascii //weight: 1
        $x_1_4 = "DKabqJxqU" ascii //weight: 1
        $x_1_5 = "HptPm5WTQo2" ascii //weight: 1
        $x_1_6 = "K98BOqJX6jh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MA_2147817168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MA!MTB"
        threat_id = "2147817168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ALUa7" ascii //weight: 3
        $x_3_2 = "PHYST2JX3" ascii //weight: 3
        $x_3_3 = "UYh41ub" ascii //weight: 3
        $x_3_4 = "Vemfa4WN" ascii //weight: 3
        $x_1_5 = "DrawThemeIcon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MA_2147817168_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MA!MTB"
        threat_id = "2147817168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "divZ.dll" ascii //weight: 1
        $x_1_3 = "AhBFjaeDCm" ascii //weight: 1
        $x_1_4 = "C3tBAq4atal" ascii //weight: 1
        $x_1_5 = "JERySppkP" ascii //weight: 1
        $x_1_6 = "JetG7TeKm1t" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MA_2147817168_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MA!MTB"
        threat_id = "2147817168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PetVersionInfo" ascii //weight: 2
        $x_2_2 = "Pava_com_sun_star_sdbcx_comp_hsqldb_StorageNativeOutputStream_write" ascii //weight: 2
        $x_2_3 = "Pomponent_getFactory" ascii //weight: 2
        $x_2_4 = "Pava_com_sun_star_sdbcx_comp_hsqldb_NativeStorageAccess" ascii //weight: 2
        $x_2_5 = "Pava_com_sun_star_sdbcx_comp_hsqldb_StorageNativeOutputStream_write__Ljava_lang_String_2Ljava_lang_String" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EH_2147817207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EH!MTB"
        threat_id = "2147817207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 55 d8 8b 12 03 55 a8 2b d0 8b 45 d8 89 10 6a 00 e8 ?? ?? ?? ?? 8b 55 c4 03 55 a4 2b d0 89 55 a0}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EH_2147817207_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EH!MTB"
        threat_id = "2147817207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {33 18 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 a1 ?? ?? ?? ?? 83 c0 04 a3 ?? ?? ?? ?? 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EH_2147817207_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EH!MTB"
        threat_id = "2147817207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 12 03 55 a8 2b d0 8b 45 d8 89 10 6a 00 e8 ?? ?? ?? ?? 8b 55 c4 03 55 a4 2b d0 89 55 a0 6a 00 e8 ?? ?? ?? ?? 8b 55 a0 2b d0 8b 45 d8 33 10}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EH_2147817207_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EH!MTB"
        threat_id = "2147817207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 97 fc 00 00 00 8b 87 44 01 00 00 8b 8f 3c 01 00 00 8b 04 82 31 04 8a}  //weight: 3, accuracy: High
        $x_2_2 = {8b 8f 44 01 00 00 8b 87 fc 00 00 00 8b b7 3c 01 00 00 8b 97 f8 00 00 00 8b 04 88 01 04 b2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EH_2147817207_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EH!MTB"
        threat_id = "2147817207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {2b d8 4b 6a 00 e8 ?? ?? ?? ?? 2b d8 4b a1 ?? ?? ?? ?? 33 18 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 a1 ?? ?? ?? ?? 83 c0 04 a3 ?? ?? ?? ?? 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EH_2147817207_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EH!MTB"
        threat_id = "2147817207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 02 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82 18 00 8b 15 ?? ?? ?? ?? 33 02 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EH_2147817207_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EH!MTB"
        threat_id = "2147817207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KUeiOQldysa" ascii //weight: 1
        $x_1_2 = "cixdSEJhjJ" ascii //weight: 1
        $x_1_3 = "ZxGsSmAIedOS" ascii //weight: 1
        $x_1_4 = "NWJLjRFAXbwtudq" ascii //weight: 1
        $x_1_5 = "GtfbsDzAFiJhwIWnol" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EH_2147817207_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EH!MTB"
        threat_id = "2147817207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UBKgkRahWzY" ascii //weight: 1
        $x_1_2 = "RallocatePositions" ascii //weight: 1
        $x_1_3 = "RapplyInsertions" ascii //weight: 1
        $x_1_4 = "LEGlyphStorage" ascii //weight: 1
        $x_1_5 = "vbeng" ascii //weight: 1
        $x_1_6 = "zccmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EH_2147817207_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EH!MTB"
        threat_id = "2147817207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wntmsci12.pro\\bin\\forui.pdb" ascii //weight: 1
        $x_1_2 = "com.sun.star.sheet.FormulaOpCodeMapEntry" ascii //weight: 1
        $x_1_3 = "for.dll" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "FORMULA_HID_FORMULA_FAP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EI_2147817228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EI!MTB"
        threat_id = "2147817228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 45 a4 e8 ?? ?? ?? ?? 8b 55 d8 8b 1a 03 5d ec 2b d8 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 89 18 8b 45 c8 03 45 a0 03 45 ec 03 45 a4 8b 55 d8 31 02 83 45 ec 04 83 45 d8 04 8b 45 ec 3b 45 d4 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EJ_2147817293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EJ!MTB"
        threat_id = "2147817293"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "bgoViRpv.dll" ascii //weight: 1
        $x_1_3 = "FLgGdjZqP" ascii //weight: 1
        $x_1_4 = "NskRX3tbj" ascii //weight: 1
        $x_1_5 = "WIF3PLnrp" ascii //weight: 1
        $x_1_6 = "kgqUXnuDf" ascii //weight: 1
        $x_1_7 = "iVkbkXWi.dll" ascii //weight: 1
        $x_1_8 = "NWqMMA8fd" ascii //weight: 1
        $x_1_9 = "kc2K7CRr" ascii //weight: 1
        $x_1_10 = "wgJKFaO" ascii //weight: 1
        $x_1_11 = "yeBp5w1iXq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_AT_2147817527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AT!MTB"
        threat_id = "2147817527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0197f2addd482f70" ascii //weight: 1
        $x_1_2 = "870ee82fcb9002bf" ascii //weight: 1
        $x_1_3 = "7ce12d8a10f4c49b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AT_2147817527_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AT!MTB"
        threat_id = "2147817527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {0f b6 07 0f b7 44 41 50 31 44 24 68 8b 44 24 10 8b 4c 24 44 41 89 4c 24 44 0f b6 80 82 0b 00 00 3b c8 0f 85}  //weight: 4, accuracy: High
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PJ_2147817589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PJ!MTB"
        threat_id = "2147817589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllRegisterServer" ascii //weight: 1
        $x_1_2 = "23980c9035eab2dbdea51e8a383e22ed9b51d5ac2712d88b" ascii //weight: 1
        $x_1_3 = "33ea69388d4d3646f501ab81f8871c6689ac235f547b5433" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Qakbot_EK_2147817590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EK!MTB"
        threat_id = "2147817590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 55 a8 03 55 ac 4a 2b d0 89 55 a4}  //weight: 3, accuracy: High
        $x_2_2 = {8b 55 d8 8b 12 03 55 a8 2b d0 8b 45 d8 89 10}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EK_2147817590_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EK!MTB"
        threat_id = "2147817590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "jnSYgdHb.dll" ascii //weight: 1
        $x_1_3 = "AfmqVSC" ascii //weight: 1
        $x_1_4 = "B3gtqxEej" ascii //weight: 1
        $x_1_5 = "C1tecXebs" ascii //weight: 1
        $x_1_6 = "D6pn8MzA" ascii //weight: 1
        $x_1_7 = "IUrgLPQr.dll" ascii //weight: 1
        $x_1_8 = "BxhlzpAY" ascii //weight: 1
        $x_1_9 = "CjXNzy4lB" ascii //weight: 1
        $x_1_10 = "F7MIlc7kJnm" ascii //weight: 1
        $x_1_11 = "JWsl7YiVW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qakbot_EL_2147817666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EL!MTB"
        threat_id = "2147817666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 2b d8 e8 ?? ?? ?? ?? 03 d8 a1 ?? ?? ?? ?? 33 18 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EO_2147817747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EO!MTB"
        threat_id = "2147817747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 d8 83 c0 04 03 45 a4 89 45 d8 8b 45 a8 3b 45 cc 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EP_2147817833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EP!MTB"
        threat_id = "2147817833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d8 8b 45 ?? 33 18 89 5d ?? 8b 45 ?? 8b 55 ?? 89 02 33 c0 89 45 ?? 8b 45 ?? 83 c0 ?? 03 45 ?? 89 45 ?? 6a 00 e8 ?? ?? ?? ?? 8b 5d ?? 83 c3 ?? 03 5d ?? 2b d8 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EP_2147817833_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EP!MTB"
        threat_id = "2147817833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "jL.dll" ascii //weight: 1
        $x_1_3 = "AupGGYVMSIX" ascii //weight: 1
        $x_1_4 = "BUQJfEhQC" ascii //weight: 1
        $x_1_5 = "CKOWsIizRdj" ascii //weight: 1
        $x_1_6 = "DMHkBWq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EQ_2147818025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EQ!MTB"
        threat_id = "2147818025"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 48 8b 55 ?? 33 02 89 45 ?? 8b 45 ?? 8b 55 ?? 89 02 33 c0 89 45 ?? 8b 45 ?? 83 c0 04 03 45 ?? 89 45 ?? 6a 00 e8 ?? ?? ?? ?? 8b 5d ?? 83 c3 04 03 5d ?? 2b d8 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EU_2147818080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EU!MTB"
        threat_id = "2147818080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 6a 66 e8 ?? ?? ?? ?? 03 d8 6a 66 e8 ?? ?? ?? ?? 2b d8 6a 66 e8 ?? ?? ?? ?? 03 d8 89 5d ?? 8b 45 ?? 8b 55 d8 01 02 8b 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ec 04 83 45 d8 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MRT_2147818087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MRT!MTB"
        threat_id = "2147818087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2c d3 2c dc 2c f6 2c 52 2c 40 2c e0 20 26 2c b1 2c e0 45 37 2c 3e 2c e0 2c 88 2c 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_ME_2147818129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.ME!MTB"
        threat_id = "2147818129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b d0 4a a1 ?? ?? ?? ?? 89 10 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 2b d8 4b 6a 00 e8 ?? ?? ?? ?? 2b d8 4b 6a 00 e8 ?? ?? ?? ?? 03 d8 a1 ?? ?? ?? ?? 33 18 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 a1 ?? ?? ?? ?? 83 c0 04 a3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EV_2147818338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EV!MTB"
        threat_id = "2147818338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d e4 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 33 f1 89 35 ?? ?? ?? ?? 8d 8d 64 ff ff ff e8 ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 33 55 f0 89 55 f0 0f b6 05 ?? ?? ?? ?? 8b 4d f0 2b c8 89 4d f0 0f b6 15 ?? ?? ?? ?? 8b 45 f0 2b c2 89 45 f0 8b 0d ?? ?? ?? ?? 03 4d ec 8a 55 f0 88 11 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EW_2147818614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EW!MTB"
        threat_id = "2147818614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 d8 8b 55 a8 01 10 8b 45 d8 8b 00 8b 55 c4 03 55 a8 03 55 ac 4a 33 c2 89 45 a0 6a 00 e8 ?? ?? ?? ?? 8b 5d a0 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 89 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PMF_2147818695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PMF!MTB"
        threat_id = "2147818695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 2b d8 6a 00 e8 [0-4] 03 d8 8b 45 d8 33 18 89 5d a0 6a 00 e8 [0-4] 8b 5d a0 2b d8 6a 00 e8 [0-4] 03 d8 8b 45 d8 89 18 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 6a 00 e8 [0-4] 8b 5d d8 83 c3 04 03 5d a4 2b d8 6a 00 e8 [0-4] 03 d8 89 5d d8 8b 45 a8 3b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PMG_2147818788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PMG!MTB"
        threat_id = "2147818788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 d8 01 18 8b 45 d8 8b 00 8b 55 c4 03 55 a8 03 55 ac 4a 33 c2 89 45 a0 6a 00 e8 [0-4] 8b 5d a0 2b d8 6a 00 e8 [0-4] 03 d8 8b 45 d8 89 18 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 6a 00 e8 [0-4] 8b 5d d8 83 c3 04 03 5d a4 2b d8 6a 00 e8 [0-4] 03 d8 89 5d d8 8b 45 a8 3b 45 cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PMH_2147819387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PMH!MTB"
        threat_id = "2147819387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 c4 03 45 a4 8b 55 d8 33 02 89 45 a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 6a 00 e8 [0-4] 8b d8 8b 45 a8 83 c0 04 03 45 a4 03 d8 6a 00 e8 [0-4] 2b d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AMF_2147819530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AMF!MTB"
        threat_id = "2147819530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllRegisterServer" ascii //weight: 1
        $x_1_2 = "I6HEWhD0y" ascii //weight: 1
        $x_1_3 = "Ig1mZDdTgN5" ascii //weight: 1
        $x_1_4 = "JaaDRuGo7nu" ascii //weight: 1
        $x_1_5 = "K3Vi19a5EZ" ascii //weight: 1
        $x_1_6 = "LkAJ2Yrbxki" ascii //weight: 1
        $x_1_7 = "MQ9ItIAAY" ascii //weight: 1
        $x_1_8 = "TCwvcaJKJ97" ascii //weight: 1
        $x_1_9 = "U9mV7ncd80e" ascii //weight: 1
        $x_1_10 = "WwvDj69m1FL" ascii //weight: 1
        $x_1_11 = "aMMoyOcrTrp" ascii //weight: 1
        $x_1_12 = "azyTZoy6OlF" ascii //weight: 1
        $x_1_13 = "e39OamtD" ascii //weight: 1
        $x_1_14 = "hDAggRsa" ascii //weight: 1
        $x_1_15 = "jMhsSRKPgHF" ascii //weight: 1
        $x_1_16 = "nYZi3CdiuP" ascii //weight: 1
        $x_1_17 = "oa1bp1wYiG7" ascii //weight: 1
        $x_1_18 = "tEDTQUksuqJ" ascii //weight: 1
        $x_1_19 = "u0PmO2w8q" ascii //weight: 1
        $x_1_20 = "v5BM2Af" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EX_2147819604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EX!MTB"
        threat_id = "2147819604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 6a 00 e8 ?? ?? ?? ?? 8b d8 8b 45 a8 83 c0 04 03 45 a4 03 d8 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PMI_2147819754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PMI!MTB"
        threat_id = "2147819754"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 c4 03 45 a4 8b 55 d8 33 02 89 45 a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 6a 00 e8 [0-4] 8b d8 8b 45 d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EZ_2147819999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EZ!MTB"
        threat_id = "2147819999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b d8 89 5d a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 6a 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_FA_2147820073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FA!MTB"
        threat_id = "2147820073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b d8 8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 6a 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_FB_2147820131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FB!MTB"
        threat_id = "2147820131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 89 5d a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 6a 00 e8 ?? ?? ?? ?? 8b d8 03 5d a0 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d8 89 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PMJ_2147820280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PMJ!MTB"
        threat_id = "2147820280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 a4 8b 45 a8 8b 55 d8 01 02 8b 45 c4 03 45 a4 89 45 a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_FC_2147820481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FC!MTB"
        threat_id = "2147820481"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 d8 89 5d a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 d8 83 c0 04 03 45 a4 89 45 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MB_2147821232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MB!MTB"
        threat_id = "2147821232"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 d8 83 c0 04 03 45 a4 89 45 d8 8b 45 a8 3b 45 cc 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MB_2147821232_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MB!MTB"
        threat_id = "2147821232"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 18 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 10 8b 45 f8 83 c0 04 4f 00 8b d8 03 1d ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_FD_2147821259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FD!MTB"
        threat_id = "2147821259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e8 8b 55 d8 01 02 8b 45 cc 03 45 ac 2d ?? ?? ?? ?? 03 45 e8 8b 55 d8 31 02 83 45 e8 04 83 45 d8 04 8b 45 e8 3b 45 d4 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d8 8b 45 d8 03 45 b0 03 45 e8 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 89 5d b4 8b 45 b4 8b 55 ec 31 02 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qakbot_FE_2147821727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FE!MTB"
        threat_id = "2147821727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 02 6a 00 e8 ?? ?? ?? ?? 8b 5d c4 03 5d a4 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 89 5d a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 6a 00 e8 ?? ?? ?? ?? 8b 5d a0 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 89 18}  //weight: 1, accuracy: Low
        $x_1_2 = {01 02 6a 00 e8 ?? ?? ?? ?? 8b d8 8b 45 c4 03 45 a4 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 89 5d a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qakbot_NA_2147822456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.NA!MTB"
        threat_id = "2147822456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 d8 8b 45 d8 89 18 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 d8 83 c0 04 03 45 a4 89 45 d8 8b 45 a8 3b 45 cc 72 89}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EVU_2147822836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EVU!MTB"
        threat_id = "2147822836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 d8 8b 45 d8 89 18 8b 45 c4 03 45 a4 89 45 a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02 8b 45 d8 83 c0 04 89 45 d8 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 a8 3b 45 cc 72 99}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EVV_2147822854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EVV!MTB"
        threat_id = "2147822854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 d8 89 5d a4 8b 45 a8 8b 55 d8 01 02 8b 45 c4 03 45 a4 89 45 a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PMK_2147822973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PMK!MTB"
        threat_id = "2147822973"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 d8 83 c0 04 03 45 a4 89 45 d8 8b 45 a8 3b 45 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_FG_2147823001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FG!MTB"
        threat_id = "2147823001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 d8 8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02 6a 00 e8 ?? ?? ?? ?? 8b 5d d8 83 c3 04 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 89 5d d8 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 a8 3b 45 cc 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_FH_2147823173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FH!MTB"
        threat_id = "2147823173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 9c 03 45 ec 89 45 a0 8b 45 d8 8b 55 ec 01 10 8b 45 c8 03 45 a0 8b 55 d8 31 02 83 45 ec 04 83 45 d8 04 8b 45 ec 3b 45 d4 0f 82}  //weight: 1, accuracy: High
        $x_1_2 = {8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02 8b 45 d8 83 c0 04 89 45 d8 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 a8 3b 45 cc 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qakbot_FI_2147823247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FI!MTB"
        threat_id = "2147823247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 18 6a 00 e8 ?? ?? ?? ?? 8b 5d c4 03 5d a4 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 89 5d a0 6a 00 e8 ?? ?? ?? ?? 8b 5d a0 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 33 18 89 5d a0 6a 00 e8 ?? ?? ?? ?? 8b 5d a0 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 89 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_FJ_2147823612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FJ!MTB"
        threat_id = "2147823612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 02 8b 45 c8 03 45 98 03 45 ec 03 45 a0 89 45 a8 6a 00 e8 ?? ?? ?? ?? 8b 5d a8 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 31 18 83 45 ec 04 83 45 d8 04 8b 45 ec 3b 45 d4 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_FK_2147823695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FK!MTB"
        threat_id = "2147823695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d8 8b 45 d8 33 18 89 5d a0 e8 ?? ?? ?? ?? 8b 5d a0 2b d8 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 89 18 8b 45 d8 83 c0 04 89 45 d8 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 a8 3b 45 cc 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_FL_2147823696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FL!MTB"
        threat_id = "2147823696"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllInstall" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "LAzXEg" ascii //weight: 1
        $x_1_4 = "NPKJBv9lq" ascii //weight: 1
        $x_1_5 = "TOdQ7602" ascii //weight: 1
        $x_1_6 = "ConnectNamedPipe" ascii //weight: 1
        $x_1_7 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_FM_2147823856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FM!MTB"
        threat_id = "2147823856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllInstall" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "DFXqm1889" ascii //weight: 1
        $x_1_4 = "JYnV8U" ascii //weight: 1
        $x_1_5 = "NkzKT1Y8" ascii //weight: 1
        $x_1_6 = "SIHW052T" ascii //weight: 1
        $x_1_7 = "TzK86601" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_FN_2147824038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FN!MTB"
        threat_id = "2147824038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 18 8b 45 c4 03 45 a4 89 45 a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 6a 00 e8 ?? ?? ?? ?? 8b 5d a0 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 89 18 6a 00 e8 ?? ?? ?? ?? 8b 5d d8 83 c3 04 2b d8 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_FO_2147824039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FO!MTB"
        threat_id = "2147824039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllInstall" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "jvmkvb114ad.dll" ascii //weight: 1
        $x_1_4 = "RqC423" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_FP_2147824195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FP!MTB"
        threat_id = "2147824195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 33 45 a0 89 45 a0 6a 00 e8 ?? ?? ?? ?? 8b 5d a0 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 89 18 8b 45 d8 83 c0 04 89 45 d8 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 a8 3b 45 cc 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MC_2147824366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MC!MTB"
        threat_id = "2147824366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d8 03 1d ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 33 18 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 10 8b 45 f8 83 c0 04}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MC_2147824366_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MC!MTB"
        threat_id = "2147824366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f af da 8d 50 ff 33 d0 89 91 fc 00 00 00 8b 81 00 01 00 00 01 41 50 8b 81 ec 00 00 00 01 41 10 8b 81 80 00 00 00 8b 91 a8 00 00 00 88 1c 02 ff 81 80 00 00 00 8b 81 c0 00 00 00 2b 81 0c 01 00 00 35 ?? ?? ?? ?? 01 81}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MC_2147824366_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MC!MTB"
        threat_id = "2147824366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OjauzyO" ascii //weight: 1
        $x_1_2 = "WDgvQI947PN7" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "DllInstall" ascii //weight: 1
        $x_1_5 = "nduktpe709bf55.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_FQ_2147824488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FQ!MTB"
        threat_id = "2147824488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "CDUJP" ascii //weight: 1
        $x_1_3 = "DLdwmp" ascii //weight: 1
        $x_1_4 = "HlVT91j" ascii //weight: 1
        $x_1_5 = "NonC2" ascii //weight: 1
        $x_1_6 = "SUn15D" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_FR_2147824859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FR!MTB"
        threat_id = "2147824859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 83 e0 ?? 8a 04 10 32 04 1f 88 04 39 47 83 ee ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_FR_2147824859_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FR!MTB"
        threat_id = "2147824859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 18 8b 45 c4 03 45 a4 89 45 a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 6a 00 e8 ?? ?? ?? ?? 8b 5d a0 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 89 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_FS_2147825201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FS!MTB"
        threat_id = "2147825201"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 d8 8b 45 d8 89 18 8b 45 c4 03 45 a4 89 45 a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 6a 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_FT_2147825406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FT!MTB"
        threat_id = "2147825406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 d8 8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 d8 83 c0 04 03 45 a4 89 45 d8 8b 45 a8 3b 45 cc 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MD_2147826033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MD!MTB"
        threat_id = "2147826033"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 d8 8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 e8 ?? ?? ?? ?? 8b d8 8b 45 d8 83 c0 04 03 45 a4 03 d8 e8 ?? ?? ?? ?? 2b d8 89 5d d8 8b 45 a8 3b 45 cc 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MD_2147826033_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MD!MTB"
        threat_id = "2147826033"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "letVersionInfo" ascii //weight: 1
        $x_1_2 = "lasqal_alloc_memory" ascii //weight: 1
        $x_1_3 = "lasqal_evaluation_context_set_base_uri" ascii //weight: 1
        $x_1_4 = "lasqal_expression_compare" ascii //weight: 1
        $x_1_5 = "lasqal_free_evaluation_context" ascii //weight: 1
        $x_1_6 = "lasqal_graph_pattern_add_sub_graph_pattern" ascii //weight: 1
        $x_10_7 = "print" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_FU_2147826284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FU!MTB"
        threat_id = "2147826284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 c4 03 45 a4 89 45 a0 8b 45 d8 8b 00 33 45 a0 89 45 a0}  //weight: 1, accuracy: High
        $x_1_2 = {03 d8 8b 45 d8 89 18 8b 45 d8 83 c0 04 89 45 d8 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 a8 3b 45 cc 0f 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qakbot_FV_2147826597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FV!MTB"
        threat_id = "2147826597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 5d a4 8b 45 ec 8b 55 d8 01 02 8b 45 c8 03 45 a4 8b 55 d8 31 02 83 45 ec 04 83 45 d8 04 8b 45 ec 3b 45 d4 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_FW_2147826785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FW!MTB"
        threat_id = "2147826785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 18 8b 45 c4 03 45 a4 89 45 a0 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 d8 8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_FX_2147827260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FX!MTB"
        threat_id = "2147827260"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 18 8b 45 c4 03 45 a4 89 45 a0 6a 00 e8 ?? ?? ?? ?? 8b 5d a0 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 33 18 89 5d a0 6a 00 e8 ?? ?? ?? ?? 8b 5d a0 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 89 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_FY_2147827768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FY!MTB"
        threat_id = "2147827768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 d8 8b 45 d8 33 18 89 5d a0}  //weight: 1, accuracy: High
        $x_1_2 = {03 d8 89 5d d8 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 a8 3b 45 cc 0f 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_FZ_2147828962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.FZ!MTB"
        threat_id = "2147828962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 d8 89 5d a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02 8b 45 d8 83 c0 04 89 45 d8 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 a8 3b 45 cc 0f 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DAT_2147829441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DAT!MTB"
        threat_id = "2147829441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e0 8b 4d f4 2b 4d f4 89 4d f4 8b 4d e8 8a 14 01 8b 75 e4 88 14 06 8a 55 f3 83 c0 01 88 55 f3 8b 7d ec 39 f8 89 45 e0 74 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SYS_2147829442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SYS!MTB"
        threat_id = "2147829442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 15 98 10 55 00 8b 0d f8 4c 5b 00 0f b6 3d ef 4c 5b 00 8b 35 0c b2 74 00 8b c1 2b 05 f8 b1 74 00 8d 14 0f 2b 05 fc 4c 5b 00 8d 6c 32 ba 0f b6 15 e7 4c 5b 00 89 2d 00 4d 5b 00 be 02 00 00 00 0f b6 9e e4 4c 5b 00 03 dd 03 5c 24 14 8d 44 18 ba 3b c2 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SB_2147833221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SB!MTB"
        threat_id = "2147833221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 86 4c 01 00 00 31 46 ?? 48 89 86 ?? ?? ?? ?? 8b 86 ?? ?? ?? ?? 2d ?? ?? ?? ?? 89 46 ?? ff 77 ?? 8b 46 ?? 03 47 ?? 50 8b 47 ?? 03 46 ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "DQFiFa0y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SC_2147833222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SC!MTB"
        threat_id = "2147833222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 96 4c 01 00 00 8b 46 ?? 41 09 ?? ?? ?? ?? ?? 8b 46 ?? 69 80 ?? ?? ?? ?? ?? ?? ?? ?? 3b c8 76}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 81 ec 00 00 00 31 86 ?? ?? ?? ?? ff 89 ?? ?? ?? ?? 8b 86 ?? ?? ?? ?? 2d ?? ?? ?? ?? 89 86 ?? ?? ?? ?? ff 77 ?? 8b 47 ?? 03 46}  //weight: 1, accuracy: Low
        $x_1_3 = "DQFiFa0y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MRU_2147833274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MRU!MTB"
        threat_id = "2147833274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 5d 08 2b cf 33 d2 8b c7 f7 75 10 8a 04 1a 8b 55 fc 32 04 17 88 04 39 47 83 ee 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_RK_2147833288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RK!MTB"
        threat_id = "2147833288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 a8 03 45 ac 48 89 45 a4}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 d8 8b 12 03 55 a8 03 c2 8b 55 d8 89 02}  //weight: 1, accuracy: High
        $x_1_3 = {03 d8 8b 45 d8 33 18 89 5d a0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AF_2147833291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AF!MTB"
        threat_id = "2147833291"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c2 8b 55 d8 89 02 68 [0-4] e8 [0-4] 8b 55 c4 03 55 a4 03 c2 89 45 a0 68 [0-4] e8 [0-4] 8b d8 03 5d a0 68 [0-4] e8 [0-4] 03 d8 8b 45 d8 33 18 89 5d a0 68 [0-4] e8 [0-4] 03 45 a0 8b 55 d8 89 02 8b 45 a8 83 c0 04 89 45 a8 33 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AQ_2147833439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AQ!MTB"
        threat_id = "2147833439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 d8 8b 45 d8 33 18 89 5d a0 6a 00 e8 [0-4] 8b d8 03 5d a0 6a 00 e8 [0-4] 03 d8 6a 00 e8 [0-4] 03 d8 6a 00 e8 [0-4] 03 d8 8b 45 d8 89 18 68 [0-4] e8 [0-4] 8b 55 d8 83 c2 04 03 c2 89 45 d8 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 a8 3b 45 cc 0f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AP_2147833536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AP!MTB"
        threat_id = "2147833536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 f8 99 f7 7d e4 8b 45 10 0f b6 0c 10 8b 55 08 03 55 f8 0f b6 02 33 c1 8b 4d 08 03 4d f8 88 01 eb}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MOH_2147833699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MOH!MTB"
        threat_id = "2147833699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c6 04 8b 82 ?? ?? ?? ?? 31 42 ?? b8 ?? ?? ?? ?? 2b 82 ?? ?? ?? ?? 01 82 ?? ?? ?? ?? 8b 42 ?? 2d ?? ?? ?? ?? 01 42 ?? 8b 82 ?? ?? ?? ?? 01 42 ?? b8 ?? ?? ?? ?? 2b 42 ?? 01 82 ?? ?? ?? ?? 8b 42 ?? 33 82 ?? ?? ?? ?? 35 ?? ?? ?? ?? 89 42 ?? 81 fe ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AS_2147833721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AS!MTB"
        threat_id = "2147833721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 d8 8b 45 d8 89 18 8b 45 c4 03 45 a4 89 45 a0}  //weight: 2, accuracy: High
        $x_2_2 = {8b 55 a0 2b d0 4a 8b 45 d8 33 10 89 55 a0 6a 00 e8 [0-4] 8b d8 03 5d a0 6a 00 e8 [0-4] 03 d8 6a 00 e8 [0-4] 03 d8 6a 00 e8 [0-4] 03 d8 8b 45 d8 89 18}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AS_2147833721_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AS!MTB"
        threat_id = "2147833721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 5f 1d 00 00 77 ?? 40 89 45 ?? 3b [0-2] 72 20 00 85 c0 74 ?? ff 15 ?? ?? ?? ?? 8b 45}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 04 39 33 f0 8b c6 c1 ee 04 83 e0 0f 33 34 85 ?? ?? ?? ?? 8b c6 c1 ee 04 83 e0 0f 33 34 85 ?? ?? ?? ?? 41 3b ca 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MM_2147833758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MM!MTB"
        threat_id = "2147833758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 82 80 00 00 00 31 42 40 b8 ?? ?? ?? ?? 2b 82 ?? ?? ?? ?? 01 82 ?? ?? ?? ?? 8b 42 48 2d ?? ?? ?? ?? 01 42 68 8b 82 ?? ?? ?? ?? 01 42 74 b8 ?? ?? ?? ?? 2b 42 30 01 82 ?? ?? ?? ?? 8b 82 d0 00 00 00 33 42 68 35 ?? ?? ?? ?? 89 42 68 81 fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_ECG_2147833992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.ECG!MTB"
        threat_id = "2147833992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 46 24 83 e8 ?? 01 86 ?? ?? ?? ?? 8b 4e ?? 8b 46 ?? 31 04 0a 83 c2 ?? 8b 46 ?? 83 e8 ?? 0f af 86 ?? ?? ?? ?? 89 86 ?? ?? ?? ?? 8b 46 ?? 01 46 ?? 81 fa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AU_2147834300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AU!MTB"
        threat_id = "2147834300"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fc ff 03 05 [0-4] 8b 15 [0-4] 33 02 a3 [0-4] a1 [0-4] 8b 15 [0-4] 89 02 a1 [0-4] 83 c0 04 a3 [0-4] 33 c0 a3 [0-4] a1 [0-4] 83 c0 04 03 05 [0-4] a3 [0-4] a1 [0-4] 3b 05 [0-4] 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MF_2147834364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MF!MTB"
        threat_id = "2147834364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 8b 45 d8 83 c0 04 03 45 a4 89 45 d8 8b 45 a8 3b 45 cc 0f 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MF_2147834364_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MF!MTB"
        threat_id = "2147834364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 50 0c 8b 48 70 8b ?? 94 00 00 00 88 1c 0a ff 40 70 8b 50 70 8b 88 94 00 00 00 8b 5c 24 28 88 1c 0a ff 40 70 8b 48 68 81 f1 ?? ?? ?? ?? 29 48 48 8b 88 80 00 00 00 09 88 c4 00 00 00 8b 88 a0 00 00 00 01 88 88 00 00 00 81 ff ?? ?? ?? ?? 0f 8c}  //weight: 10, accuracy: Low
        $x_2_2 = "DllRegisterServer" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MF_2147834364_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MF!MTB"
        threat_id = "2147834364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 6d 76 5f 61 64 64 5f 69 00}  //weight: 1, accuracy: High
        $x_1_2 = "mv_adler32_update" ascii //weight: 1
        $x_1_3 = "mv_aes_alloc" ascii //weight: 1
        $x_1_4 = "mv_aes_ctr_increment_iv" ascii //weight: 1
        $x_1_5 = "mv_assert0_fpu" ascii //weight: 1
        $x_1_6 = "mv_blowfish_crypt" ascii //weight: 1
        $x_1_7 = "mv_audio_fifo_drain" ascii //weight: 1
        $x_1_8 = "mv_audio_fifo_peek_at" ascii //weight: 1
        $x_1_9 = "mv_camellia_crypt" ascii //weight: 1
        $x_1_10 = "next" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GPA_2147834415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GPA!MTB"
        threat_id = "2147834415"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 75 08 8b c1 83 e0 7f 8a 04 30 32 04 39 0f b6 c0 66 89 04 5a 43 41 3b 5d fc 72}  //weight: 1, accuracy: High
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "DllInstall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AX_2147834493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AX!MTB"
        threat_id = "2147834493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {56 8b 75 10 57 8b f8 85 f6 74 0d 2b d0 8a 0c 3a 88 0f 47 83 ee 01 75}  //weight: 4, accuracy: High
        $x_1_2 = {0b 01 0e 00 00 d8 00 00 00 9c 04 00 00 00 00 00 60 e7 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SF_2147834496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SF!MTB"
        threat_id = "2147834496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5c 24 28 81 e9 ?? ?? ?? ?? 0f af 88 ?? ?? ?? ?? c1 eb ?? 89 88 ?? ?? ?? ?? 8b 48 ?? 8d 91 ?? ?? ?? ?? 0b d1 89 50}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 48 68 81 f1 ?? ?? ?? ?? 29 48 ?? 8b 88 ?? ?? ?? ?? 09 88 ?? ?? ?? ?? 8b 88 ?? ?? ?? ?? 01 88 ?? ?? ?? ?? 81 ff ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_DIO_2147834517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DIO!MTB"
        threat_id = "2147834517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 ca 83 c2 04 31 01 8b 86 ?? ?? ?? ?? 31 46 40 b8 ?? ?? ?? ?? 2b 86 ?? ?? ?? ?? 01 86 ?? ?? ?? ?? 8b 46 48 2d ?? ?? ?? ?? 01 46 68 8b 86 ?? ?? ?? ?? 01 46 74 b8 ?? ?? ?? ?? 2b 46}  //weight: 1, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AZ_2147834568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AZ!MTB"
        threat_id = "2147834568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b d8 4b 8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 6a 00 e8 [0-4] 8b 55 d8 83 c2 04 03 55 a4 03 c2 40 89 45 ?? 8b 45 ?? 3b 45 ?? 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_AW_2147834570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.AW!MTB"
        threat_id = "2147834570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {99 f7 7d ec 8b 45 10 0f b6 14 10 03 ca 88 4d ff 0f b6 45 ff 8b 4d 08 03 4d f8 0f b6 11 33 d0 8b 45 08 03 45 f8 88 10 0f b6 4d f0 8b 45 f8 99 f7 7d ec 8b 45 10 0f b6 14 10 2b ca 88 4d ff e9}  //weight: 4, accuracy: High
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SAB_2147834671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SAB!MTB"
        threat_id = "2147834671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 0f af 46 ?? 89 46 ?? 8b 46 ?? 2d ?? ?? ?? ?? 31 46 ?? 8b 46 ?? 35 ?? ?? ?? ?? 29 46 ?? 8b 86 ?? ?? ?? ?? 09 86 ?? ?? ?? ?? 8b 86 ?? ?? ?? ?? 01 86 ?? ?? ?? ?? 81 fb ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GT_2147834827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GT!MTB"
        threat_id = "2147834827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b d8 8b 45 d8 33 18 89 5d a0 8b 45 d8 8b 55 a0 89 10 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 8b 45 d8 83 c0 04 03 45 a4 89 45 d8 8b 45 a8 3b 45 cc 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_RPN_2147834844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RPN!MTB"
        threat_id = "2147834844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 a8 03 45 ac 48 89 45 a4 8b 45 d8 8b 55 a8 01 10 8b 45 c4 03 45 a4 89 45 a0}  //weight: 1, accuracy: High
        $x_1_2 = {33 18 89 5d a0 8b 45 d8 8b 55 a0 89 10 8b 45 a8 83 c0 04 89 45 a8 33 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GU_2147834922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GU!MTB"
        threat_id = "2147834922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 18 89 1d [0-15] 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 a1 ?? ?? ?? ?? 83 c0 04 a3 ?? ?? ?? ?? 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GV_2147834995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GV!MTB"
        threat_id = "2147834995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 8b 45 d8 89 18 8b 45 c4 03 45 a4 89 45 a0 [0-15] 8b d8 03 5d a0 [0-15] 2b d8 8b 45 d8 33 18 89 5d a0 8b 45 d8 8b 55 a0 89 10 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BD_2147835236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BD!MTB"
        threat_id = "2147835236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {01 43 78 8b 83 b0 00 00 00 83 e8 0c 31 43 48 b8 5a 4c 0c 00 2b 83 94 00 00 00 2b 43 2c 01 83 a4 00 00 00 8b 53 48 8b 43 14 81 c2 1b 03 f3 ff 03 93 94 00 00 00 05 0f 98 05 00 0f af 53 64 89 53 64 03 83 10 01 00 00 33 c2 89 43 64 8b 83 a4 00 00 00 05 13 98 05 00 03 83 10 01 00 00 01 43 48 8b 83 a0 00 00 00 35 80 7a 33 34 01 43 48 81 fd c0 65 04 00 0f}  //weight: 4, accuracy: High
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MSD_2147835253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MSD!MTB"
        threat_id = "2147835253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 34 28 83 c5 04 8b 43 7c 31 43 48 8b c1 2b 43 78 35 ?? ?? ?? ?? 0f af 43 10 89 43 10 33 c0 40 2b c1 01 83 ?? ?? ?? ?? 8b 43 2c 8b 53 60 35 ?? ?? ?? ?? 0f af 43 2c 0f af d6 89 43 2c 8b 4b 68 8b 83 ?? ?? ?? ?? 88 14 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_TG_2147835292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.TG!MTB"
        threat_id = "2147835292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c7 89 43 10 33 c0 40 2b c1 8b 4b 68 01 83 ?? ?? ?? ?? 8b c6 35 ?? ?? ?? ?? 0f af c6 89 43 2c 0f b6 c2 0f b6 53 60 0f af d0 8b 83 ?? ?? ?? ?? 88 14 01}  //weight: 1, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BE_2147835402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BE!MTB"
        threat_id = "2147835402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {2b c1 8b 4d 64 89 41 1c 8b 55 64 8b 42 48 35 c4 4e 0e 00 8b 4d 64 03 81 d0 00 00 00 8b 55 64 89 82 d0 00 00 00 e9}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MKE_2147835413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MKE!MTB"
        threat_id = "2147835413"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4a 18 2b 88 ?? ?? ?? ?? 8b 55 ?? 89 4a ?? 8b 45 ?? 8b 88 ?? ?? ?? ?? 8b 55 ?? 8b 45 ?? 8b 0c 91 33 88 ?? ?? ?? ?? 8b 55 ?? 8b 82}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 04 00 00 00 c1 e0 ?? 8b 4d ?? 8b 55 ?? 8b 84 01 ?? ?? ?? ?? 33 42 ?? 05 ?? ?? ?? ?? 8b 4d ?? 8b 51 ?? 2b d0 8b 45 ?? 89 50 ?? 8b 4d ?? 8b 51 ?? 83 ea ?? 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BF_2147835417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BF!MTB"
        threat_id = "2147835417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b d8 6a 00 e8 [0-4] 2b d8 a1 [0-4] 33 18 89 1d [0-4] a1 [0-4] 8b 15 [0-4] 89 02 6a 00 e8 [0-4] 8b d8 a1 [0-4] 83 c0 04 03 d8 6a 00 e8 [0-4] 2b d8 89 1d [0-4] 33 c0 a3 [0-4] a1 [0-4] 83 c0 04 03 05 [0-4] a3 [0-4] a1 [0-4] 3b 05 [0-4] 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BG_2147835486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BG!MTB"
        threat_id = "2147835486"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "broadbill" ascii //weight: 1
        $x_1_2 = "enlargeableness" ascii //weight: 1
        $x_1_3 = "lipped" ascii //weight: 1
        $x_1_4 = "monotheist" ascii //weight: 1
        $x_1_5 = "pharyngemphraxis" ascii //weight: 1
        $x_1_6 = "scribbleomania" ascii //weight: 1
        $x_1_7 = "platypod" ascii //weight: 1
        $x_1_8 = "unturpentined" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BH_2147835576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BH!MTB"
        threat_id = "2147835576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 7d e4 89 55 ?? 8b 45 ?? 03 45 ?? 0f b6 08 8b 55 ?? 03 55 ?? 0f b6 02 33 c1 8b 4d ?? 03 4d ?? 88 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BH_2147835576_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BH!MTB"
        threat_id = "2147835576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b d3 c1 ea 08 88 14 01 ff 47 50 8b 87 b8 00 00 00 8b 4f 50 35 83 00 75 06 09 47 28 29 47 20 8b 47 78 88 1c 01 ff 47 50 8b 47 68 2d [0-4] 01 87 b8 00 00 00 8b 87 ac 00 00 00 35 [0-4] 29 47 14 8b 87 94 00 00 00 8b 4f 68 03 c8 81 f1 [0-4] 03 c8 8b 47 44 33 47 08 2d [0-4] 89 8f 94 00 00 00 09 47 14 81 fe [0-4] 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GX_2147835660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GX!MTB"
        threat_id = "2147835660"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pcrha024ay68.dll" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "owner dead" ascii //weight: 1
        $x_1_4 = "ConnectNamedPipe" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_QBT_2147835675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.QBT!MTB"
        threat_id = "2147835675"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 ea 01 d1 81 c1 ?? ?? ?? ?? 89 4f 58 8b 4c 24 24 0f af 01 89 c1 c1 e9 10 8b 57 6c 8b af ?? ?? ?? ?? 8d 72 01 89 77 6c 88 4c 15 00 8b 4f 2c 8d 91 ?? ?? ?? ?? 8b b7 ?? ?? ?? ?? bd ?? ?? ?? ?? 29 cd}  //weight: 1, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MH_2147835678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MH!MTB"
        threat_id = "2147835678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 56 4c 8b be ?? ?? ?? ?? 8d 5a 01 89 5e 4c 88 0c 17 8b 4e 4c 8b 96 ?? ?? ?? ?? 8d 79 01 89 7e 4c 88 24 0a 8b 4e 4c 8b 96 ?? ?? ?? ?? 8d 79 01 89 7e 4c 88 04 0a 8b 86 18 01 00 00 33 86}  //weight: 10, accuracy: Low
        $x_5_2 = "DllRegisterServer" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MH_2147835678_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MH!MTB"
        threat_id = "2147835678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xairo_append_path" ascii //weight: 1
        $x_1_2 = "xairo_arc_negative" ascii //weight: 1
        $x_1_3 = "xairo_clip_preserve" ascii //weight: 1
        $x_1_4 = "xairo_copy_path_flat" ascii //weight: 1
        $x_1_5 = "xairo_debug_reset_static_data" ascii //weight: 1
        $x_1_6 = "xairo_device_get_reference_count" ascii //weight: 1
        $x_1_7 = "xairo_device_get_user_data" ascii //weight: 1
        $x_1_8 = "xairo_device_to_user_distance" ascii //weight: 1
        $x_1_9 = "xairo_ft_font_face_create_for_pattern" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BI_2147835773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BI!MTB"
        threat_id = "2147835773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 4d e6 8b 55 08 03 55 e0 0f b6 02 33 c1 8b 4d 08 03 4d e0 88 01 8d 55 e8 52 8d 4d e8}  //weight: 2, accuracy: High
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "DllUnregisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_NZA_2147836082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.NZA!MTB"
        threat_id = "2147836082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 a0 2b d0 8b 45 d8 33 10 89 55 a0 8b 45 d8 8b 55 a0 89 10 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 8b 45 d8 83 c0 04 03 45 a4 89 45 d8 8b 45 a8 3b 45 cc 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MI_2147836229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MI!MTB"
        threat_id = "2147836229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 c8 3b 45 cc 73 ?? 6a ?? e8 ?? ?? ?? ?? 8b 55 f4 03 55 c8 8b 45 ec 03 45 c4 8b 4d d4 e8 ?? ?? ?? ?? 8b 45 d4 01 45 c4 8b 45 d4 01 45 c8 8b 45 d0 01 45 c8 eb ?? 8b 45 e8}  //weight: 10, accuracy: Low
        $x_10_2 = {03 d8 8b 45 ec 31 18 6a 00 e8 ?? ?? ?? ?? 8b 55 e8 83 c2 04 03 c2 89 45 e8 8b 45 ec 83 c0 04 89 45 ec 8b 45 e8 3b 45 e4 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SAC_2147836292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SAC!MTB"
        threat_id = "2147836292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 34 83 c2 ?? 8b 4c 24 ?? 8b 81 ?? ?? ?? ?? 0f af 81 ?? ?? ?? ?? 8b 7c 24 ?? 31 f8 39 c2 8b 6c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {d1 5a 41 00 59 d1 8b 00 95 33 cd 00 44 b5 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {be 53 47 00 ba 57 53 00 ff 96 46 00 09 be 80 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SAE_2147836366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SAE!MTB"
        threat_id = "2147836366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b f8 8b 43 ?? 89 bb ?? ?? ?? ?? 31 04 29 83 c5 ?? 8b 4b ?? 49 01 4b ?? 8b 8b ?? ?? ?? ?? 01 4b ?? 81 fd ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BJ_2147836401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BJ!MTB"
        threat_id = "2147836401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DllUnregisterServer" ascii //weight: 2
        $x_2_2 = "concertizer" ascii //weight: 2
        $x_2_3 = "isoparaffin" ascii //weight: 2
        $x_2_4 = "pseudobrachial" ascii //weight: 2
        $x_2_5 = "tapperer" ascii //weight: 2
        $x_2_6 = "bodywork" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BK_2147836416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BK!MTB"
        threat_id = "2147836416"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 5d a0 2b d8 6a 00 e8 [0-4] 2b d8 8b 45 d8 33 18 89 5d a0 6a 00 e8 [0-4] 8b 55 a0 2b d0 8b 45 d8 89 10 6a 00 e8 [0-4] 8b 55 a8 83 c2 04 2b d0 89 55 a8 33 c0 89 45 a4 8b 45 d8 83 c0 04 03 45 a4 89 45 d8 8b 45 a8 3b 45 cc 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SAF_2147836437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SAF!MTB"
        threat_id = "2147836437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 8b 46 ?? 89 9e ?? ?? ?? ?? 31 04 29 83 c5 ?? 8b 46 ?? 48 01 46 ?? 8b 46 ?? 01 46 ?? 81 fd ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BL_2147836556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BL!MTB"
        threat_id = "2147836556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 d8 6a 00 e8 [0-4] 2b d8 a1 [0-4] 33 18 89 1d [0-4] 6a 00 e8 [0-4] 6a 00 e8 [0-4] 6a 00 e8 [0-4] 6a 00 e8 [0-4] 6a 00 e8 [0-4] a1 [0-4] 8b 15 [0-4] 89 02 a1 [0-4] 83 c0 04 a3 [0-4] 33 c0 a3 [0-4] a1 [0-4] 83 c0 04 03 05 [0-4] a3 [0-4] a1 [0-4] 3b 05 [0-4] 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GZ_2147836611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GZ!MTB"
        threat_id = "2147836611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "out.dll" ascii //weight: 1
        $x_1_2 = "DrawThemeIcon" ascii //weight: 1
        $x_1_3 = "aldhafara" ascii //weight: 1
        $x_1_4 = "DllUnregisterServer" ascii //weight: 1
        $x_1_5 = "breastheight" ascii //weight: 1
        $x_1_6 = "marmorean" ascii //weight: 1
        $x_1_7 = "soniou" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_RDA_2147837021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RDA!MTB"
        threat_id = "2147837021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ccleaner.exe" wide //weight: 1
        $x_1_2 = "CCleaner" wide //weight: 1
        $x_1_3 = "psoriatiform" ascii //weight: 1
        $x_1_4 = "meconophagism" ascii //weight: 1
        $x_1_5 = "starchman" ascii //weight: 1
        $x_1_6 = "DllUnregisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_HA_2147837057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.HA!MTB"
        threat_id = "2147837057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "whnm109ro08.dll" ascii //weight: 1
        $x_1_2 = "DrawThemeIcon" ascii //weight: 1
        $x_1_3 = "RYJdw8455dzS" ascii //weight: 1
        $x_1_4 = "FdFA9B7N" ascii //weight: 1
        $x_1_5 = "ZgYT0t4i" ascii //weight: 1
        $x_1_6 = "CwmUcg86" ascii //weight: 1
        $x_1_7 = "CbNB0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_HB_2147837058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.HB!MTB"
        threat_id = "2147837058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 10 8b 45 c4 03 45 a4 89 45 a0 [0-7] 8b 5d a0 2b d8 [0-7] 2b d8 8b 45 d8 33 18 89 5d a0 [0-7] 8b 5d a0 2b d8 [0-7] 2b d8 [0-7] 2b d8 8b 45 d8 89 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_NZ_2147837131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.NZ!MTB"
        threat_id = "2147837131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c1 2b c8 8b 86 ?? ?? ?? ?? 05 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 31 46 ?? b8 ?? ?? ?? ?? 2b 46 ?? 01 86 ?? ?? ?? ?? 8b 86 ?? ?? ?? ?? 89 8e ?? ?? ?? ?? 8b 8e ?? ?? ?? ?? 31 04 11 83 c2 ?? 8b 86 ?? ?? ?? ?? 01 86 ?? ?? ?? ?? 81 fa ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BO_2147837181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BO!MTB"
        threat_id = "2147837181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "apetaloid" ascii //weight: 1
        $x_1_2 = "ladykind" ascii //weight: 1
        $x_1_3 = "overindulge" ascii //weight: 1
        $x_1_4 = "spirometer" ascii //weight: 1
        $x_1_5 = "townless" ascii //weight: 1
        $x_1_6 = "zaparoan" ascii //weight: 1
        $x_1_7 = "graben" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_KD_2147837184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.KD!MTB"
        threat_id = "2147837184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "petPluginInfoW" ascii //weight: 1
        $x_1_2 = "ppenW" ascii //weight: 1
        $x_1_3 = "pxitFAR" ascii //weight: 1
        $x_1_4 = "petGlobalInfoW" ascii //weight: 1
        $x_1_5 = "petMinFarVersion" ascii //weight: 1
        $x_1_6 = "petMinFarVersionW" ascii //weight: 1
        $x_1_7 = "petPluginInfo" ascii //weight: 1
        $x_1_8 = "ppenPlugin" ascii //weight: 1
        $x_1_9 = "ppenPluginW" ascii //weight: 1
        $x_1_10 = "processSynchroEventW" ascii //weight: 1
        $x_1_11 = "petStartupInfo" ascii //weight: 1
        $x_1_12 = "ConEmuTh.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BP_2147837229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BP!MTB"
        threat_id = "2147837229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 55 d8 03 55 b4 2b d0 8b 45 ec 31 10 6a 00 e8 [0-4] 8b d8 8b 45 e8 83 c0 04 03 d8 6a 00 e8 [0-4] 2b d8 6a 00 e8 [0-4] 03 d8 6a 00 e8 [0-4] 2b d8 89 5d e8 8b 45 ec 83 c0 04 89 45 ec 8b 45 e8 3b 45 e4 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BQ_2147837480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BQ!MTB"
        threat_id = "2147837480"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 2b d8 a1 [0-4] 33 18 89 1d}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 12 03 15 [0-4] 03 c2 8b 15 [0-4] 89 02 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_HBA_2147837491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.HBA!MTB"
        threat_id = "2147837491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 75 08 8b c1 83 e0 7f 8a 04 30 32 04 39 0f b6 c0 66 89 04 5a 43 41 3b 5d fc 72}  //weight: 1, accuracy: High
        $x_1_2 = "mnjhuiv40" ascii //weight: 1
        $x_1_3 = "aeroflot" ascii //weight: 1
        $x_1_4 = "Jjischug" ascii //weight: 1
        $x_1_5 = "DrawThemeIcon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SAH_2147837545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SAH!MTB"
        threat_id = "2147837545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 02 42 47 83 c6 ?? 8b c6 83 d1 ?? 0b c1 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c1 83 e0 ?? 8a 44 30 ?? 30 04 11 41 3b cf 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SAI_2147837677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SAI!MTB"
        threat_id = "2147837677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 3e 8b 4d ?? 02 c2 0f b6 c0 8a 04 38 30 04 ?? 43 8a 45 0b 3b 5d ?? 7c}  //weight: 1, accuracy: Low
        $x_1_2 = "Updt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BR_2147837694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BR!MTB"
        threat_id = "2147837694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 d0 0f be 02 89 85 d8 fe ff ff 8b 4d 8c 33 8d d8 fe ff ff 89 4d 8c 8b 55 d0 83 c2 01 89 55 d0 33 c0 74 09 8b 4d d0 83 c1 01 89 4d d0 eb}  //weight: 1, accuracy: High
        $x_1_2 = {03 72 14 8b 85 70 ff ff ff 8b 7d f4 03 78 0c 8b 49 10 f3 a4 8b 8d 70 ff ff ff 83 c1 28 89 8d 70 ff ff ff eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_QQ_2147837733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.QQ!MTB"
        threat_id = "2147837733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 89 45 10 89 55 ?? fe 45 ?? 0f b6 45 ?? 8a 54 08 04 00 55 ff 8d 74 08 ?? 0f b6 45 ?? 8d 7c 08 ?? 8a 44 08 ?? 88 06 03 c2 25 ?? ?? ?? ?? 88 17 8b 55 ?? 8a 44 08 ?? 32 04 1a 88 03 43 ff 4d ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = "Updt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PL_2147837921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PL!MTB"
        threat_id = "2147837921"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Updt" ascii //weight: 1
        $x_1_2 = "GetKeyboardState" ascii //weight: 1
        $x_1_3 = "GetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BT_2147838123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BT!MTB"
        threat_id = "2147838123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 d8 43 8b 45 d8 33 18 89 5d a0 6a 00 e8 [0-4] 8b 5d a0 2b d8 6a 00 e8 [0-4] 2b d8 6a 00 e8 [0-4] 2b d8 8b 45 d8 89 18 6a 00 e8 [0-4] 8b 55 a8 83 c2 04 2b d0 89 55 a8 33 c0 89 45 a4 6a 00 e8 [0-4] 8b 5d d8 83 c3 04 03 5d a4 2b d8 6a 00 e8 [0-4] 2b d8 6a 00 e8 [0-4] 03 d8 89 5d d8 8b 45 a8 3b 45 cc 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_HC_2147840009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.HC!MTB"
        threat_id = "2147840009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 03 1d ?? ?? ?? ?? 43 [0-7] 03 d8 43 a1 ?? ?? ?? ?? 33 18 89 1d [0-11] 8b 1d ?? ?? ?? ?? 2b d8 [0-7] 2b d8 [0-7] 2b d8 a1 ?? ?? ?? ?? 89 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BU_2147840025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BU!MTB"
        threat_id = "2147840025"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 e8 8b 55 ec 01 02 6a 00 e8 [0-4] 8b 55 d8 03 55 e4 03 55 e8 2b d0 8b 45 ec 31 10 83 45 e8 04 e8 [0-4] bb 04 00 00 00 2b d8 e8 [0-4] 03 d8 01 5d ec 8b 45 e8 3b 45 e0 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BV_2147840026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BV!MTB"
        threat_id = "2147840026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UMGFLT_InitDDEEnhance" ascii //weight: 1
        $x_1_2 = "UMGFLT_CloseDDEColor" ascii //weight: 1
        $x_1_3 = "UMGFLT_CloseMoire" ascii //weight: 1
        $x_1_4 = "UMGFLT_InitMoire" ascii //weight: 1
        $x_1_5 = "UMGFLT_CloseResize" ascii //weight: 1
        $x_1_6 = "UMGFLT_InitFocus" ascii //weight: 1
        $x_1_7 = "UMGFLT_CloseDDEBin" ascii //weight: 1
        $x_1_8 = "UMGFLT_InitDDEColor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BW_2147840165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BW!MTB"
        threat_id = "2147840165"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 00 33 05 [0-4] a3 [0-4] 6a 00 e8 [0-4] 8b 1d [0-4] 2b d8 6a 00 e8 [0-4] 2b d8 6a 00 e8 [0-4] 2b d8 a1 [0-4] 89 18 a1 [0-4] 83 c0 04 a3 [0-4] 33 c0 a3 [0-4] 6a 00 e8 [0-4] 8b 15 [0-4] 83 c2 04 03 15 [0-4] 03 c2 40 a3 [0-4] a1 [0-4] 3b 05 [0-4] 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_HD_2147840182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.HD!MTB"
        threat_id = "2147840182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 33 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 89 18 a1 ?? ?? ?? ?? 83 c0 04 a3 ?? ?? ?? ?? 33 c0 a3 17 00 01 10 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SAK_2147840183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SAK!MTB"
        threat_id = "2147840183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 33 05 ?? ?? ?? ?? a3 3c 00 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 48 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 01 10 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SAL_2147840184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SAL!MTB"
        threat_id = "2147840184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 e3 bb 00 00 00 00 e9 ?? ?? ?? ?? 8b 45 ?? 0f b6 44 10 ?? 33 c8 3a f6 74 ?? 8b 45 ?? 03 45 ?? 0f b6 08 3a c0 74}  //weight: 1, accuracy: Low
        $x_1_2 = "Wind" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_RPO_2147840235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RPO!MTB"
        threat_id = "2147840235"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VisibleEntry" ascii //weight: 1
        $x_1_2 = "banago" ascii //weight: 1
        $x_1_3 = "defaulture" ascii //weight: 1
        $x_1_4 = "epicorolline" ascii //weight: 1
        $x_1_5 = "existentialist" ascii //weight: 1
        $x_1_6 = "hypopharyngeal" ascii //weight: 1
        $x_1_7 = "nicenian" ascii //weight: 1
        $x_1_8 = "slaveland" ascii //weight: 1
        $x_1_9 = "violetwise" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SAN_2147840430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SAN!MTB"
        threat_id = "2147840430"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f6 3a db 74 ?? bb ?? ?? ?? ?? 03 e3 bb ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b 45 ?? 0f b6 44 10 ?? 33 c8 66 ?? ?? 74}  //weight: 1, accuracy: Low
        $x_1_2 = "Wind" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_CNG_2147840491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.CNG!MTB"
        threat_id = "2147840491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 85 d8 33 c2 eb 01 40 80 3c 08 00 75 f9 c9 c3}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 dc 38 5b 5b 4d}  //weight: 1, accuracy: High
        $x_1_3 = {8a 44 0d dc 04 09 88 44 0d c0 41 83 f9 1b 7c f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SAQ_2147840526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SAQ!MTB"
        threat_id = "2147840526"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f6 3a db 74 ?? bb ?? ?? ?? ?? 03 e3 bb ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b 45 ?? 0f b6 44 10 ?? 33 c8 66 ?? ?? 74}  //weight: 1, accuracy: Low
        $x_1_2 = "Wind" ascii //weight: 1
        $x_1_3 = "UT_Sin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SAR_2147840527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SAR!MTB"
        threat_id = "2147840527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 08 8b 45 ?? 66 ?? ?? 74 ?? 83 e8 ?? 8b 4d ?? 83 d9 ?? eb ?? 40 89 45 ?? 8b 45 ?? 3a db 74}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 08 66 ?? ?? 74 ?? 8b 45 ?? 0f b6 44 10 ?? 33 c8 3a c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_HE_2147840535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.HE!MTB"
        threat_id = "2147840535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 ec 03 45 f0 0f b6 08 3a f6 74 ?? 8b 45 fc 0f b6 44 10 10 33 c8 66 3b ed 74 ?? 8b 45 ec 03 45 f0 88 08 e9 ?? ?? ?? ?? e9 ?? ?? ?? ?? 53 5e f7 f6 66 3b c0 74}  //weight: 1, accuracy: Low
        $x_1_2 = "wind" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PM_2147840594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PM!MTB"
        threat_id = "2147840594"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Wind" ascii //weight: 1
        $x_1_2 = {8b 45 fc 0f b6 44 10 ?? 33 c8 [0-4] 8b 45 ?? 03 45 ?? 88 08 8b 45 ?? 40 89 45 ?? 8b 45 ?? 3b 45 ?? 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MJ_2147840930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MJ!MTB"
        threat_id = "2147840930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {e0 8b 45 e0 dc 49 01 00 74 25 e9 01 54 31 05 83 78 0c 00 74 45 ba 40 d8 8b 4d fc e9 9b 3b 05}  //weight: 10, accuracy: High
        $x_2_2 = "Wind" ascii //weight: 2
        $x_2_3 = "SZ13defaultConfigv" ascii //weight: 2
        $x_2_4 = "SZ19KCONFIG_WIDGETS_LOGv" ascii //weight: 2
        $x_2_5 = "SZN10KTipDialogD0Ev" ascii //weight: 2
        $x_2_6 = "SZN12KCodecActionD0Ev" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_GEO_2147840993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.GEO!MTB"
        threat_id = "2147840993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SZ13defaultConfigv" ascii //weight: 1
        $x_1_2 = "SZN10KTipDialogD2Ev" ascii //weight: 1
        $x_1_3 = "SZN12KCodecActionD2Ev" ascii //weight: 1
        $x_1_4 = "SZN12KTipDatabase7Private7addTipsERK7QString" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
        $x_1_6 = "SZN5QHashI7QStringP7QWidgetE13duplicateNodeEPN9QHashData4NodeEPv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_HF_2147841006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.HF!MTB"
        threat_id = "2147841006"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 04 a3 3f 00 01 10 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 40 8b 15 ?? ?? ?? ?? 33 02 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 10 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_HG_2147841014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.HG!MTB"
        threat_id = "2147841014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 4c 05 ?? 8b 45 ?? 33 d2 66 3b ff 74 ?? bb ?? ?? ?? ?? 53 5e 66 3b f6 74 ?? 8b 4d ?? 03 48 ?? 89 4d ?? 66 3b d2 74 ?? f7 f6 0f b6 44 15 ?? 33 c8 e9 ?? ?? ?? ?? ff 75 ?? 8b 45 ?? ff 70 ?? 3a f6 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BX_2147841075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BX!MTB"
        threat_id = "2147841075"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 5d d8 03 5d b4 2b d8 6a 00 e8 [0-4] 03 d8 8b 45 ec 31 18 6a 00 e8 [0-4] 8b d8 8b 45 e8 83 c0 04 03 d8 6a 00 e8 [0-4] 2b d8 6a 00 e8 [0-4] 03 d8 6a 00 e8 [0-4] 2b d8 89 5d e8 8b 45 ec 83 c0 04 89 45 ec 8b 45 e8 3b 45 e4 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_BY_2147841384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.BY!MTB"
        threat_id = "2147841384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 bc 8b 45 fc 8b 40 0c eb b1 8b 45 fc 0f b6 44 10 10 33 c8 3a f6 74 00 8b 45 ec 03 45 f0 88 08 e9}  //weight: 1, accuracy: High
        $x_1_2 = {83 e8 01 8b 4d 14 83 d9 00 eb c5 40 89 45 f8 8b 45 10 66 3b db 74 e9 8a 09 88 08 8b 45 fc 66 3b c0 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SAS_2147841449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SAS!MTB"
        threat_id = "2147841449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 ec 03 45 ?? 0f b6 08 3a f6 74 ?? 8b 45 ?? 0f b6 44 10 ?? 33 c8 66 ?? 74}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 ec 03 45 ?? 88 08 e9 ?? ?? ?? ?? e9 ?? ?? ?? ?? 53 5e f7 f6 66 ?? ?? 74}  //weight: 1, accuracy: Low
        $x_1_3 = "Wind" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_CC_2147842107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.CC!MTB"
        threat_id = "2147842107"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "L_cms15Fixed16toDouble@4" ascii //weight: 1
        $x_1_2 = "L_cmsCreateMutex@4" ascii //weight: 1
        $x_1_3 = "LcmsBuildGamma@12" ascii //weight: 1
        $x_1_4 = "L_cmsDestroyMutex@8" ascii //weight: 1
        $x_1_5 = "L_cmsGetTransformUserData@4" ascii //weight: 1
        $x_1_6 = "LcmsAdaptToIlluminant@16" ascii //weight: 1
        $x_1_7 = "LcmsCreateLab4ProfileTHR@8" ascii //weight: 1
        $x_1_8 = "LcmsDesaturateLab@36" ascii //weight: 1
        $x_1_9 = "LcmsIT8SetPropertyUncooked@12" ascii //weight: 1
        $x_1_10 = "LcmsxyY2XYZ@8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_CD_2147842244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.CD!MTB"
        threat_id = "2147842244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "L?0?$allocator@VPathArcArgs@Magick@@@std@@QAE@XZ" ascii //weight: 1
        $x_1_2 = "L?0Blob@Magick@@QAE@XZ" ascii //weight: 1
        $x_1_3 = "L?0Color@Magick@@QAE@GGGG@Z" ascii //weight: 1
        $x_1_4 = "L?0Color@Magick@@QAE@PBD@Z" ascii //weight: 1
        $x_1_5 = "L?0Coordinate@Magick@@QAE@NN@Z" ascii //weight: 1
        $x_1_6 = "L?0DrawableBezier@Magick@@QAE@ABV01@@Z" ascii //weight: 1
        $x_1_7 = "L?0DrawableFillRule@Magick@@QAE@W4FillRule@MagickCore@@@Z" ascii //weight: 1
        $x_1_8 = "L?0DrawableStrokeAntialias@Magick@@QAE@_N@Z" ascii //weight: 1
        $x_1_9 = "LstrokeMiterLimit@Image@Magick@@QAEXI@Z" ascii //weight: 1
        $x_1_10 = "Lswirl@Image@Magick@@QAEXN@Z" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SAT_2147842445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SAT!MTB"
        threat_id = "2147842445"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 10 a1 5c ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 33 02 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 10 a1 ?? ?? ?? ?? 83 c0 ?? a3 ?? ?? ?? ?? 33 c0 a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_RDB_2147842631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RDB!MTB"
        threat_id = "2147842631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b d1 8b 4d fc 2b d7 8b c7 83 e0 7f 8a 04 18 32 04 0f 88 04 3a 47 83 ee 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_RDB_2147842631_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RDB!MTB"
        threat_id = "2147842631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kkcs11h_certificate_decrypt" ascii //weight: 1
        $x_1_2 = "kkcs11h_addProvider" ascii //weight: 1
        $x_1_3 = "kkcs11h_terminate" ascii //weight: 1
        $x_1_4 = "kkcs11h_openssl_createSession" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PO_2147842808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PO!MTB"
        threat_id = "2147842808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d3 89 46 ?? 8b 86 ?? ?? ?? ?? 33 06 01 46 ?? 8b 4e ?? 33 0e 81 e9 [0-4] c1 ea 08 09 4e ?? 8b 46 ?? 8b 4e ?? 88 14 01 8b 86 ?? ?? ?? ?? ff 46 ?? 05 ?? ?? ?? ?? 03 46 ?? 09 46 ?? 8b 56 ?? 8b 46 ?? 88 1c 02 ff 46 ?? 8b 46 ?? 2b 86 [0-4] 05 [0-4] 31 86 [0-4] 81 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PP_2147842809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PP!MTB"
        threat_id = "2147842809"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xlAutoOpen" ascii //weight: 1
        $x_1_2 = "ZMDGyz104wqz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PR_2147842891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PR!MTB"
        threat_id = "2147842891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 bb 04 00 00 00 53 5e f7 f6 0f b6 44 15 ?? 66 3b d2 33 c8 8b 45 ?? 88 4c 05 ?? e9 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b 40 ?? 8b 4d ?? 8d 44 01 ?? 66 3b ed 89 45 ?? bb d2 04 00 00 53 66 3b ed}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SJN_2147842904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SJN!MTB"
        threat_id = "2147842904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 a3 c0 8d ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 01 10 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 33 02 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 10 a1 ?? ?? ?? ?? 83 c0 ?? a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SJM_2147842905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SJM!MTB"
        threat_id = "2147842905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 10 00 00 00 03 e3 eb ?? f7 f6 8b 45 ?? 0f b6 44 10 ?? 66 3b c9 74 ?? 33 c8 8b 45 ?? 03 45 ?? e9 ?? ?? ?? ?? 0f b6 08 8b 45 ?? 33 d2 66 3b f6 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PS_2147842944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PS!MTB"
        threat_id = "2147842944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 14 31 8b 0d [0-4] 33 15 [0-4] 89 14 0e 83 c6 04 8b 0d [0-4] 81 c1 [0-4] 0f af 48 ?? 89 48 ?? 8b 0d [0-6] 88 [0-4] 8b 0d [0-4] 8b 49 [0-4] 2b 0d [0-4] 83 e9 [0-4] 0f af 88 [0-4] 89 88 [0-4] 8b 0d [0-4] 81 f1 [0-4] 29 88 [0-4] 81 fe [0-4] 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PU_2147843119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PU!MTB"
        threat_id = "2147843119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 bb 04 00 00 00 53 5e f7 f6 0f b6 44 ?? a8 66 3b c9 33 c8 8b 45 ?? 88 4c ?? ac 8b 45 ?? 40 89 45 ?? 83 7d ?? 04 8b 45 ?? 89 45 ?? 8b 45 ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PV_2147843294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PV!MTB"
        threat_id = "2147843294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 66 3b ed bb 08 00 00 00 53 5e 3a f6 f7 f6 8b 45 ?? 0f b6 44 10 ?? 66 3b c0 33 c8 8b 45 ?? 03 45 ?? 88 08 8b 45 ?? 40 89 45 ?? 8b 45 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_CEB_2147843380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.CEB!MTB"
        threat_id = "2147843380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GL70" ascii //weight: 1
        $x_1_2 = "Cpgme_data_identify" ascii //weight: 1
        $x_1_3 = "Cpgme_data_new" ascii //weight: 1
        $x_1_4 = "Cpgme_data_new_from_cbs" ascii //weight: 1
        $x_1_5 = "Cpgme_data_new_from_estream" ascii //weight: 1
        $x_1_6 = "Cpgme_io_write" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_CF_2147843417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.CF!MTB"
        threat_id = "2147843417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 f8 03 05 [0-4] 48 a3 [0-4] 6a 00 e8 [0-4] 8b d8 a1 [0-4] 8b 00 03 45 f8 03 d8 6a 00 e8 [0-4] 03 d8 a1 [0-4] 89 18 a1 [0-4] 03 05 [0-4] a3 [0-4] a1 [0-4] 8b 00 33 05 [0-4] a3 [0-4] a1 [0-4] 8b 15 [0-4] 89 10 8b 45 f8 83 c0 04 89 45 f8 33 c0 a3 [0-4] a1 [0-4] 83 c0 04 03 05 [0-4] a3 [0-4] 8b 45 f8 3b 05 [0-4] 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_RC_2147844189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.RC!MTB"
        threat_id = "2147844189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c8 8b 45 ec 66 3b e4 74 0b 03 45 f0 0f b6 08 66 3b f6 74 e1 03 45 f0 88 08 e9 3f 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PX_2147844558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PX!MTB"
        threat_id = "2147844558"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 3a c0 bb 08 00 00 00 53 66 3b f6 5e f7 f6 66 3b c0 8b 45 ?? 0f b6 44 10 ?? 66 3b c0 33 c8 8b 45 ?? 3a db 03 45 ?? 88 08 8b 45 ?? 40 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_CH_2147844587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.CH!MTB"
        threat_id = "2147844587"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "J_gmp_limbroots_table" ascii //weight: 1
        $x_1_2 = "J_gmp_primesieve" ascii //weight: 1
        $x_1_3 = "J_gmp_default_fp_limb_precision" ascii //weight: 1
        $x_1_4 = "J_gmp_asprintf_memory" ascii //weight: 1
        $x_1_5 = "J_gmp_rands_initialized" ascii //weight: 1
        $x_1_6 = "J_gmp_tmp_reentrant_alloc" ascii //weight: 1
        $x_1_7 = "J_gmp_urandomm_ui" ascii //weight: 1
        $x_1_8 = "J_gmpf_fits_slong_p" ascii //weight: 1
        $x_1_9 = "J_gmpf_get_default_prec" ascii //weight: 1
        $x_1_10 = "J_gmpf_urandomb" ascii //weight: 1
        $x_1_11 = "J_gmpn_addmul_1_p6_sse2" ascii //weight: 1
        $x_1_12 = "J_gmpn_bc_mulmod_bnm1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_CI_2147844746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.CI!MTB"
        threat_id = "2147844746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "S_clean_type_info_names_internal" ascii //weight: 1
        $x_1_2 = "S__unguarded_readlc_active_add_func" ascii //weight: 1
        $x_1_3 = "S_CxxUnregisterExceptionObject" ascii //weight: 1
        $x_1_4 = "SUnlock_shared_ptr_spin_lock" ascii //weight: 1
        $x_1_5 = "SLock_shared_ptr_spin_lock" ascii //weight: 1
        $x_1_6 = "Swhat@exception@std@@UBEPBDXZ" ascii //weight: 1
        $x_1_7 = "Stry_lock@critical_section@Concurrency@@QAE_NXZ" ascii //weight: 1
        $x_1_8 = "Slock@reader_writer_lock@Concurrency@@QAEXXZ" ascii //weight: 1
        $x_1_9 = "Sismbbkalnum_l" ascii //weight: 1
        $x_1_10 = "Sseh_longjmp_unwind" ascii //weight: 1
        $x_1_11 = "Socaleconv" ascii //weight: 1
        $x_1_12 = "Sexecvpe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PY_2147844789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PY!MTB"
        threat_id = "2147844789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 3a e4 bb 08 00 00 00 53 3a db 5e f7 f6 66 3b c0 8b 45 ?? 0f b6 44 10 10 3a ff 33 c8 8b 45 ?? 3a e4 03 45 ?? 88 08 8b 45 ?? 40 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_CJ_2147844817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.CJ!MTB"
        threat_id = "2147844817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Il_directory_completion_hook" ascii //weight: 1
        $x_1_2 = "Ii_movement_keymap" ascii //weight: 1
        $x_1_3 = "Irl_add_executing_keyseq" ascii //weight: 1
        $x_1_4 = "Irl_bracketed_read_mbstring" ascii //weight: 1
        $x_1_5 = "Irl_vi_domove_motion_cleanup" ascii //weight: 1
        $x_1_6 = "Iopy_history_entry" ascii //weight: 1
        $x_1_7 = "Iistory_quotes_inhibit_expansion" ascii //weight: 1
        $x_1_8 = "Il_call_last_kbd_macro" ascii //weight: 1
        $x_1_9 = "Il_completion_word_break_hook" ascii //weight: 1
        $x_1_10 = "Iilde_expansion_preexpansion_hook" ascii //weight: 1
        $x_1_11 = "Ih_unset_nodelay_mode" ascii //weight: 1
        $x_1_12 = "Il_set_paren_blink_timeout" ascii //weight: 1
        $x_1_13 = "Nikn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PZ_2147844912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PZ!MTB"
        threat_id = "2147844912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 66 3b c0 bb 04 00 00 00 53 66 3b ed 5e f7 f6 66 3b db 0f b6 44 15 ?? 33 c8 3a ed 8b 45 ?? 88 4c 05 ?? 8b 45 ?? 40 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_CT_2147845234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.CT!MTB"
        threat_id = "2147845234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 ec 28 64 a1 30 00 00 00 3a e4 74 16}  //weight: 1, accuracy: High
        $x_1_2 = {89 45 e0 8b 45 e0 3a f6 74 bf}  //weight: 1, accuracy: High
        $x_1_3 = {8b 40 0c 8b 40 0c 66 3b e4 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {8b 00 8b 00 66 3b c9 74 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PT_2147845254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PT!MTB"
        threat_id = "2147845254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 89 45 08 8b 45 08 80 78 02 00 74 21 33 c0 ba 80 00 00 00 8b c8 80 b1 20 f8 09 00 09 41 3b ca 72 f4 80 b0 50 f0 09 00 aa 40 3b c2 72 f4 8b 4d 0c e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PT_2147845254_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PT!MTB"
        threat_id = "2147845254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 c3 33 c0 c3 33 c0 c3}  //weight: 1, accuracy: High
        $x_1_2 = {8b d1 c7 45 [0-6] 66 c7 45 [0-6] 8a 44 15 ?? 34 ab 88 44 15 ?? 42 83 fa ?? 7c ?? 88 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_CL_2147845259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.CL!MTB"
        threat_id = "2147845259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JSL_CTX_set_default_passwd_cb_userdata" ascii //weight: 1
        $x_1_2 = "JSL_CTX_set_session_id_context" ascii //weight: 1
        $x_1_3 = "JSL_COMP_add_compression_method" ascii //weight: 1
        $x_1_4 = "JSL_get_ex_data_X509_STORE_CTX_idx" ascii //weight: 1
        $x_1_5 = "JIO_new_buffer_ssl_connect" ascii //weight: 1
        $x_1_6 = "JSL_CTX_get_quiet_shutdown" ascii //weight: 1
        $x_1_7 = "JSL_check_private_key" ascii //weight: 1
        $x_1_8 = "JSL_CTX_use_certificate_file" ascii //weight: 1
        $x_1_9 = "JSL_CTX_add_server_custom_ext" ascii //weight: 1
        $x_1_10 = "JSL_CTX_set_alpn_protos" ascii //weight: 1
        $x_1_11 = "JSL_CTX_set_next_protos_advertised_cb" ascii //weight: 1
        $x_1_12 = "JRP_generate_client_master_secret" ascii //weight: 1
        $x_1_13 = "JRR_load_SSL_strings" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SJO_2147845356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SJO!MTB"
        threat_id = "2147845356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f6 8b 45 ?? eb ?? e8 ?? ?? ?? ?? bb ?? ?? ?? ?? 66 3b c9 74 ?? 53 5e 66 3b f6 74 ?? 0f b6 44 10 ?? 33 c8 e9 ?? ?? ?? ?? 33 d2 bb ?? ?? ?? ?? 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SJP_2147845435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SJP!MTB"
        threat_id = "2147845435"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 30 8b 40 0c 66 3b c9 74 ?? 8b 40 ?? 8b 4d ?? eb ?? 83 ec ?? bb ?? ?? ?? ?? 66 3b c0 74 ?? 3b 48 ?? 72 ?? 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_CN_2147845618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.CN!MTB"
        threat_id = "2147845618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ILLForceUpdateCheck" ascii //weight: 1
        $x_1_2 = "ILLGetOptionalParam" ascii //weight: 1
        $x_1_3 = "ILLOnApplicationStartup" ascii //weight: 1
        $x_1_4 = "ILLOnApplicationUninstall" ascii //weight: 1
        $x_1_5 = "ILLSetExecutorPath" ascii //weight: 1
        $x_1_6 = "Motd" ascii //weight: 1
        $x_1_7 = "ILLDownloadAndInstallSilentUpdate" ascii //weight: 1
        $x_1_8 = "ILLGetUniqUserId" ascii //weight: 1
        $x_1_9 = "ILLIsUpdateAvailable" ascii //weight: 1
        $x_1_10 = "ILLSetUniqueParam" ascii //weight: 1
        $x_1_11 = "ILLSetUpdateDestination" ascii //weight: 1
        $x_1_12 = "ILLIsUpgradeAvailable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_HH_2147845639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.HH!MTB"
        threat_id = "2147845639"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 18 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 10 2f 00 89 18 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 8b d8 03 1d ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 03 d8 a1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_HI_2147845713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.HI!MTB"
        threat_id = "2147845713"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 15 a0 33 c8 66 3b ff 74 ?? 8b 45 ?? 8b 40 ?? 3a db 74 ?? 8b 45 ?? 0f b6 4c 05 ?? 66 3b f6 74 ?? 8b 4d ?? 8d 44 01 ?? 3a c9 74}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 04 00 00 00 53 66 3b c0 74 ?? 8b 45 ?? 33 d2 66 3b ff 74 ?? 89 45 ?? bb ?? ?? ?? ?? eb ?? 8b 45 ?? 88 4c 05 ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_CO_2147845794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.CO!MTB"
        threat_id = "2147845794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 3b e4 74 ?? 8b 4d 14 83 d9 00 3a ed 74 ?? c3 89 45 10 89 4d 14 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "BEX_GetInfo" ascii //weight: 1
        $x_1_3 = "BEX_Initialize" ascii //weight: 1
        $x_1_4 = "BEX_SetCallBacks" ascii //weight: 1
        $x_1_5 = "BEX_AddParameter" ascii //weight: 1
        $x_1_6 = "BEX_Finalize" ascii //weight: 1
        $x_1_7 = "BEX_ExecuteRead" ascii //weight: 1
        $x_1_8 = "BEX_ExecuteTry" ascii //weight: 1
        $x_1_9 = "BEX_ExecuteWrite" ascii //weight: 1
        $x_1_10 = "B@Utils2@Initialize" ascii //weight: 1
        $x_1_11 = "B@Utils2@Finalize" ascii //weight: 1
        $x_1_12 = "GG10" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_CP_2147845904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.CP!MTB"
        threat_id = "2147845904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "B?0?$WeakImplHelper1@VXInteractionHandler2@task@star@sun@com@@@cppu@@QAE@XZ" ascii //weight: 1
        $x_1_2 = "B?0XMLNamespaces@framework@@QAE@XZ" ascii //weight: 1
        $x_1_3 = "B?1ActionTriggerPropertySet@framework@@UAE@XZ" ascii //weight: 1
        $x_1_4 = "B?1UndoManagerHelper@framework@@QAE@XZ" ascii //weight: 1
        $x_10_5 = "GG10" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_CQ_2147846108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.CQ!MTB"
        threat_id = "2147846108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "P?0?$BaseHash@VOUString@rtl@@@framework@@QAE@XZ" ascii //weight: 1
        $x_1_2 = "P?0ConstItemContainer@framework@@QAE@ABV01@@Z" ascii //weight: 1
        $x_1_3 = "P?0HandlerCFGAccess@framework@@QAE@ABV01@@Z" ascii //weight: 1
        $x_1_4 = "P?0ItemContainer@framework@@QAE@ABVShareableMutex@1@@Z" ascii //weight: 1
        $x_1_5 = "P?0LockHelper@framework@@QAE@PAVIMutex@vos@@@Z" ascii //weight: 1
        $x_10_6 = "Time" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_CR_2147846611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.CR!MTB"
        threat_id = "2147846611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "maptor_alloc_memory" ascii //weight: 1
        $x_1_2 = "maptor_avltree_iterator_is_end" ascii //weight: 1
        $x_1_3 = "maptor_basename" ascii //weight: 1
        $x_1_4 = "maptor_bnodeid_ntriples_write" ascii //weight: 1
        $x_1_5 = "maptor_domain_get_label" ascii //weight: 1
        $x_1_6 = "maptor_free_option_description" ascii //weight: 1
        $x_1_7 = "maptor_free_sax2" ascii //weight: 1
        $x_1_8 = "maptor_namespaces_namespace_in_scope" ascii //weight: 1
        $x_10_9 = "print" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_CREQ_2147846643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.CREQ!MTB"
        threat_id = "2147846643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "masqal_alloc_memory" ascii //weight: 1
        $x_1_2 = "masqal_evaluation_context_set_rand_seed" ascii //weight: 1
        $x_1_3 = "masqal_feature_from_uri" ascii //weight: 1
        $x_1_4 = "masqal_free_expression" ascii //weight: 1
        $x_1_5 = "masqal_free_service" ascii //weight: 1
        $x_1_6 = "masqal_graph_pattern_get_flattened_triples" ascii //weight: 1
        $x_10_7 = "print" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_HJ_2147846857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.HJ!MTB"
        threat_id = "2147846857"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 40 04 8b 4d f8 eb ?? f7 f6 0f b6 44 15 ?? 3a d2 74 ?? 53 5e 3a e4 74 ?? 8d 44 01 ?? 89 45 ?? e9 ?? ?? ?? ?? 33 d2 bb 04 00 00 00 3a c0 74 ?? 33 c8 8b 45 ?? eb ?? 89 45 ?? 8b 45 ?? 3a ed 74}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c8 8b 45 ?? e9 ?? ?? ?? ?? 0f b6 4c 05 ?? 8b 45 ?? 66 3b e4 74 ?? 8d 44 01 ?? 89 45 ?? e9 ?? ?? ?? ?? 8b 40 ?? 8b 4d ?? eb ?? 40 89 45 ?? e9 ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 66 3b ed 74 ?? 33 d2 bb 04 00 00 00 3a d2 74 ?? a5 bb ?? ?? ?? ?? e9 ?? ?? ?? ?? f7 f6 0f b6 44 15 ?? 3a c9 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qakbot_NIV_2147846873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.NIV!MTB"
        threat_id = "2147846873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 01 83 c1 04 8b f8 c1 ef 10 81 e7 ff 00 00 00 8b 3c bd 38 78 0a 4d 8b d8 c1 eb 08 81 e3 ff 00 00 00 33 3c 9d 38 7c 0a 4d 8b d8 c1 eb 18 33 3c 9d 38 74 0a 4d 25 ff 00 00 00 33 3c 85 38 80 0a 4d 83 ee 04 83 ea 01 8b c7 75 b5}  //weight: 1, accuracy: High
        $x_1_2 = "print" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PAF_2147846942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PAF!MTB"
        threat_id = "2147846942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "n?0B3dCamera@@QAE@ABV0@@Z" ascii //weight: 1
        $x_1_2 = "n?0B3dTransformationSet@@QAE@XZ" ascii //weight: 1
        $x_1_3 = "n?0DirEntry@@QAE@W4DirEntryFlag@@@Z" ascii //weight: 1
        $x_1_4 = "n?0INetURLObject@@QAE@ABV0@@Z" ascii //weight: 1
        $x_1_5 = "n?0Polygon@@QAE@ABVRectangle@@@Z" ascii //weight: 1
        $x_1_6 = "n?5@YAAAVSvStream@@AAV0@AAVColor@@@Z" ascii //weight: 1
        $x_10_7 = "print" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PAG_2147846968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PAG!MTB"
        threat_id = "2147846968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 bb 04 00 00 00 53 5e 3a ed f7 f6 0f b6 44 15 ?? 66 3b d2 33 c8 8b 45 ?? 88 4c 05 ?? 8b 45 ?? eb 00 40 89 45 ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = "print" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_HK_2147847044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.HK!MTB"
        threat_id = "2147847044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllRegisterServer" ascii //weight: 1
        $x_1_2 = "FUHJMn90" ascii //weight: 1
        $x_1_3 = "PDBFR0173R" ascii //weight: 1
        $x_1_4 = "UrccB70P" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_CREL_2147847128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.CREL!MTB"
        threat_id = "2147847128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "P<Dispose>@Exception@Platform@@U$AAAXXZ" ascii //weight: 1
        $x_1_2 = "P?0Attribute@Metadata@Platform@@Q$AAA@XZ" ascii //weight: 1
        $x_1_3 = "P?0COMException@Platform@@Q$AAA@HP$AAVString@1@@Z" ascii //weight: 1
        $x_1_4 = "P?0OutOfMemoryException@Platform@@Q$AAA@XZ" ascii //weight: 1
        $x_1_5 = "P?0int32@default@@QAA@H@Z" ascii //weight: 1
        $x_1_6 = "PGetHashCode@Attribute@Metadata@Platform@@Q$AAAHXZ" ascii //weight: 1
        $x_10_7 = "Test" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_HL_2147847173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.HL!MTB"
        threat_id = "2147847173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c8 8b 45 ?? 66 3b d2 74 ?? 8b 45 ?? 0f b6 44 10 ?? 66 3b db 74 ?? 66 89 45 ?? bb ?? ?? ?? ?? 66 3b ff 74 ?? 66 89 45 ?? bb ?? ?? ?? ?? 3a c0 74 ?? 66 89 45 ?? bb ?? ?? ?? ?? 66 3b c9 74 ?? 53 58 3a ff 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PAH_2147847343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PAH!MTB"
        threat_id = "2147847343"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 66 3b d2 bb 04 00 00 00 53 3a d2 5e f7 f6 3a c9 0f b6 44 15 ?? 33 c8 3a d2 8b 45 ?? 88 4c 05 ?? 8b 45 ?? 40 e9}  //weight: 1, accuracy: Low
        $x_1_2 = "vips" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_HM_2147847505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.HM!MTB"
        threat_id = "2147847505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c8 8b 45 ?? eb ?? 55 8b ec eb ?? 8b 45 ?? 0f b6 04 10 eb ?? 51 bb ?? ?? ?? ?? eb ?? 8b 45 ?? 03 45 ?? eb ?? 40 89 45 ?? eb ?? 99 f7 7d ?? eb ?? 03 45 ?? 88 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PAJ_2147847857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PAJ!MTB"
        threat_id = "2147847857"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 7d 14 8b 45 ?? 0f b6 04 10 33 c8 8b 45 ?? 03 45 ?? 88 08 8b 45 ?? 40 89 45 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_HN_2147848488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.HN!MTB"
        threat_id = "2147848488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 10 ?? 3a ff 74 ?? 03 45 ?? 88 08 e9 ?? ?? ?? ?? e9 ?? ?? ?? ?? 5e f7 f6 66 3b c9 74 ?? 83 c3 ?? 53 66 3b c9 74 ?? 21 5d ?? 8d 45 ?? eb ?? 53 58 3a e4 74 ?? c1 e0 ?? 8b 44 05 ?? 3a ed 74 ?? 33 c8 8b 45 ?? 66 3b c9 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PAL_2147849038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PAL!MTB"
        threat_id = "2147849038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iZN10BeatDetectC1EP3PCM" ascii //weight: 1
        $x_1_2 = "i_GLEW_AMD_shader_stencil_export" ascii //weight: 1
        $x_1_3 = "i_GLEW_ARB_shadow_ambient" ascii //weight: 1
        $x_1_4 = "i_WGLEW_EXT_create_context_es2_profile" ascii //weight: 1
        $x_1_5 = "i_glewDeleteFragmentShaderATI" ascii //weight: 1
        $x_1_6 = "i_glewDeleteProgramPipelines" ascii //weight: 1
        $x_1_7 = "i_glewMultiTexSubImage3DEXT" ascii //weight: 1
        $x_1_8 = "i_glewPassTexCoordATI" ascii //weight: 1
        $x_1_9 = "ilc_entry_license__3_0_0f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_PN_2147849703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.PN!MTB"
        threat_id = "2147849703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e4 bb 04 00 00 00 eb 2c 03 c1 89 45 f0 eb 37 03 41 18 89 45 f4 eb e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_MBFK_2147850121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.MBFK!MTB"
        threat_id = "2147850121"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kairo_append_path" ascii //weight: 1
        $x_1_2 = "kairo_close_path" ascii //weight: 1
        $x_1_3 = "kairo_debug_reset_static_data" ascii //weight: 1
        $x_1_4 = "kairo_destroy" ascii //weight: 1
        $x_1_5 = "kairo_device_get_reference_count" ascii //weight: 1
        $x_1_6 = "kairo_font_options_get_hint_metrics" ascii //weight: 1
        $x_1_7 = "kairo_font_options_get_subpixel_order" ascii //weight: 1
        $x_1_8 = "kairo_glyph_allocate" ascii //weight: 1
        $x_1_9 = "kairo_image_surface_create_for_data" ascii //weight: 1
        $x_1_10 = "kairo_matrix_transform_distance" ascii //weight: 1
        $x_1_11 = "kairo_pattern_add_color_stop_rgba" ascii //weight: 1
        $x_1_12 = "kairo_pdf_surface_restrict_to_version" ascii //weight: 1
        $x_1_13 = "kairo_region_xor" ascii //weight: 1
        $x_1_14 = "kairo_xml_create_for_stream" ascii //weight: 1
        $x_1_15 = "must" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SAA_2147852148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SAA"
        threat_id = "2147852148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 [0-255] 2c 00 [0-5] 77 00 69 00 6e 00 64 00}  //weight: 10, accuracy: Low
        $x_10_2 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 [0-255] 2c 00 [0-5] 69 00 6e 00 69 00 74 00}  //weight: 10, accuracy: Low
        $x_10_3 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 [0-255] 2c 00 [0-5] 6d 00 75 00 73 00 74 00}  //weight: 10, accuracy: Low
        $n_100_4 = {2e 00 64 00 6c 00 6c 00 [0-16] 77 00 69 00 6e 00 64 00}  //weight: -100, accuracy: Low
        $n_100_5 = {2e 00 64 00 6c 00 6c 00 [0-16] 69 00 6e 00 69 00 74 00}  //weight: -100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_Qakbot_VL_2147892639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.VL!MTB"
        threat_id = "2147892639"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b 46 0c 01 86 28 01 00 00 8b 86 24 01 00 00 35 9d 88 f2 ff c1 ea 08 01 86 2c 01 00 00 8b 86 b8 00 00 00 88 14 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_VIS_2147901381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.VIS!MTB"
        threat_id = "2147901381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 44 15 a8 33 c8 3a d2 74 00 8b 45 f4 88 4c 05 ac e9 8a 00 00 00 e9 79 ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "X555" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_SE_2147902111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SE!MTB"
        threat_id = "2147902111"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5f 54 31 47 ?? 8b 87 ?? ?? ?? ?? 8b 0c 28 83 c5 ?? 8b 87 ?? ?? ?? ?? 2d ?? ?? ?? ?? 0f af d9 31 47 ?? 8b 47}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 47 20 2d ?? ?? ?? ?? 31 47 ?? 8b 87 ?? ?? ?? ?? 05 ?? ?? ?? ?? 03 c1 01 47 ?? 8b 87 ?? ?? ?? ?? 88 1c 06 ff 47 ?? 81 fd ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Qakbot_SAO_2147902115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.SAO!MTB"
        threat_id = "2147902115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 7d e4 33 55 ?? 89 55 ?? 8b 55 ?? 03 55 ?? 0f b6 02 8b 4d ?? 03 4d ?? 0f b6 11 33 d0 8b 45 ?? 03 45 ?? 88}  //weight: 1, accuracy: Low
        $x_1_2 = "VisibleEntry" ascii //weight: 1
        $x_1_3 = "toxicologic" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbot_EAXX_2147935735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.EAXX!MTB"
        threat_id = "2147935735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 75 f4 03 c6 03 45 f4 8b 0d ?? ?? ?? ?? 03 4d f4 03 4d f4 03 4d f4 8b 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 8a 04 06 88 04 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

