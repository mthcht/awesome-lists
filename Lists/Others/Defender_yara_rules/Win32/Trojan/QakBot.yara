rule Trojan_Win32_QakBot_G_2147744602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.G!MTB"
        threat_id = "2147744602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 f0 f6 e2 8b 75 ?? 8b 7d ?? 8a 14 3e 88 45 ?? 80 f6 ?? 88 75 ?? 2b 4d ?? 8b 5d ?? 88 14 3b 01 cf 8b 4d ?? 39 cf 89 7d ?? 75 10 00 8b 45 ?? b9 ?? ?? ?? ?? b2 ?? 8a 75 ?? 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_AG_2147755285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.AG!MTB"
        threat_id = "2147755285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 3b db 0f 84 ?? ?? ?? ?? c1 e0 00 8b 4d ?? eb ?? c7 44 01 ?? ?? ?? ?? ?? 81 44 01 40 43 46 01 00 eb ?? c7 44 01 ?? ?? ?? ?? ?? 81 44 01 40 14 ad 00 00 3a c9 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = {3a f6 0f 84 ?? ?? ?? ?? c7 44 01 ?? ?? ?? ?? ?? 81 6c 01 ?? ?? ?? ?? ?? 66 3b ff 0f 84 35 00 c7 44 01 ?? ?? ?? ?? ?? 81 44 01 40 9e 32 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_2147766443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.MT!MTB"
        threat_id = "2147766443"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 08 5d c3 30 00 31 0d ?? ?? ?? ?? eb 00 c7 05 [0-8] a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d}  //weight: 1, accuracy: Low
        $x_1_2 = "c:\\mirc\\mirc.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_MV_2147769937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.MV!MTB"
        threat_id = "2147769937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 08 5f 5d c3 28 00 8b [0-5] 33 [0-5] 8b ?? 89 15 [0-4] a1 [0-4] 8b 0d}  //weight: 2, accuracy: Low
        $x_1_2 = "c:\\mirc\\mirc.ini" wide //weight: 1
        $x_1_3 = "C:\\Mirc\\mirc.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_QakBot_MW_2147770412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.MW!MTB"
        threat_id = "2147770412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 74 3b 8b [0-3] 3b [0-5] 72 02 eb 2e 8b [0-3] 03 [0-3] 8b [0-3] 03 [0-3] 68 [0-4] ff [0-5] 03 [0-3] 8b [0-3] 8a [0-3] 88 [0-3] 8b [0-3] 83 [0-3] 89 [0-3] eb}  //weight: 1, accuracy: Low
        $x_1_2 = {89 11 33 c0 e9 28 00 a1 [0-4] c7 05 [0-8] 01 05 [0-6] 8b 0d [0-4] 8b 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_MY_2147770422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.MY!MTB"
        threat_id = "2147770422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 08 5f 5d c3 45 00 b9 29 00 00 00 b9 29 00 00 00 b9 29 00 00 00 [0-32] 8b 15 [0-4] 33 05 [0-4] 8b d0 89 15 [0-4] a1 [0-4] 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_MX_2147771440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.MX!MTB"
        threat_id = "2147771440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 08 5f 5d c3 28 00 8b [0-5] 33 [0-5] 8b ?? 89 15 [0-4] a1 [0-4] 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_MZ_2147781489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.MZ!MTB"
        threat_id = "2147781489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 08 8b e5 5d c3 23 00 8b [0-5] 33 ?? c7 [0-9] 01 [0-5] a1 [0-4] 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_RPE_2147815872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.RPE!MTB"
        threat_id = "2147815872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 50 46 30 0c 54 64 72 68 79 6d 77 34 6f 69 35 6a 0b 64 72 68 79 6d 77 34 6f 69 35 6a 04 4c 65 66 74 03 50 01 03 54 6f 70 03 87 00 05 57 69 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_RPE_2147815872_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.RPE!MTB"
        threat_id = "2147815872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b d8 4b 8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_AN_2147815992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.AN!MTB"
        threat_id = "2147815992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DllRegisterServer" ascii //weight: 2
        $x_2_2 = "I6HEWhD0y" ascii //weight: 2
        $x_2_3 = "Ig1mZDdTgN5" ascii //weight: 2
        $x_2_4 = "JaaDRuGo7nu" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_AN_2147815992_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.AN!MTB"
        threat_id = "2147815992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DHjhKN8j1" ascii //weight: 1
        $x_1_2 = "DatJEtACAKW" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "E921yVgXT0J" ascii //weight: 1
        $x_1_5 = "IT0lVmz3" ascii //weight: 1
        $x_1_6 = "NyMo15M" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_BB_2147816038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.BB!MTB"
        threat_id = "2147816038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 5d a0 6a 00 e8 [0-4] 2b d8 8b 45 d8 33 18 89 5d a0 8b 45 d8 8b 55 a0 89 10 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 8b 45 d8 83 c0 04 03 45 a4 89 45 d8 8b 45 a8 3b 45 cc 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_BB_2147816038_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.BB!MTB"
        threat_id = "2147816038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "CsV6CbGXBG" ascii //weight: 3
        $x_3_2 = "DLDR5FUYj" ascii //weight: 3
        $x_3_3 = "DllRegisterServer" ascii //weight: 3
        $x_3_4 = "StrFormatByteSizeEx" ascii //weight: 3
        $x_3_5 = "SetStdHandle" ascii //weight: 3
        $x_3_6 = "FlushFileBuffers" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_BC_2147816039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.BC!MTB"
        threat_id = "2147816039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Cc5hivBg" ascii //weight: 3
        $x_3_2 = "Cmq8VwCRF" ascii //weight: 3
        $x_3_3 = "DllRegisterServer" ascii //weight: 3
        $x_3_4 = "DuNhM906" ascii //weight: 3
        $x_3_5 = "DxM0Ioe" ascii //weight: 3
        $x_3_6 = "ScriptStringXtoCP" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_BC_2147816039_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.BC!MTB"
        threat_id = "2147816039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b d8 6a 00 e8 [0-4] 2b d8 a1 [0-4] 33 18 89 1d [0-4] 6a 00 e8 [0-4] 8b d8 03 1d [0-4] 6a 00 e8 [0-4] 03 d8 6a 00 e8 [0-4] 03 d8 6a 00 e8 [0-4] 03 d8 6a 00 e8 [0-4] 03 d8 a1 [0-4] 89 18 6a 00 e8 [0-4] 8b d8 a1 [0-4] 83 c0 04 03 d8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_BC_2147816039_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.BC!MTB"
        threat_id = "2147816039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f af da 8b d3 c1 ea 08 88 14 01 ff 47 68 8b 4f 68 8b 87 b4 00 00 00 88 1c 01 8b 47 78 ff 47 68 35 40 77 20 00 29 47 6c 8b 87 c0 00 00 00 2b 47 6c 2d [0-4] 31 47 78 8b 47 74 2d [0-4] 01 47 64 8b 47 64 83 c0 ed 01 87 80 00 00 00 81 fd [0-4] 0f}  //weight: 4, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_BA_2147816155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.BA!MTB"
        threat_id = "2147816155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 0f 88 01 41 83 ea ?? 75 f5}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c1 83 e0 ?? 8a 44 10 ?? 30 04 31 41 3b cf 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_BA_2147816155_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.BA!MTB"
        threat_id = "2147816155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d8 03 1d [0-4] 6a 00 e8 [0-4] 2b d8 a1 [0-4] 33 18 89 1d [0-4] 6a 00 e8 [0-4] 03 05 [0-4] 8b 15 [0-4] 89 02 a1 [0-4] 83 c0 04 a3 [0-4] 33 c0 a3 [0-4] a1 [0-4] 83 c0 04 03 05 [0-4] a3 [0-4] a1 [0-4] 3b 05 [0-4] 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_BA_2147816155_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.BA!MTB"
        threat_id = "2147816155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "C3zIsbR4udA" ascii //weight: 3
        $x_3_2 = "CC6PsF" ascii //weight: 3
        $x_3_3 = "CbJVyQ098vd" ascii //weight: 3
        $x_3_4 = "DllRegisterServer" ascii //weight: 3
        $x_3_5 = "GetCommandLineA" ascii //weight: 3
        $x_3_6 = "FindFirstFileExW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_CM_2147816156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.CM!MTB"
        threat_id = "2147816156"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {ff 75 14 ff 75 10 3a c9 74 e1 33 ed c1 e8 f6 f7 fd f7 df c1 ef 00 0b d9 81 ea 89 25 00 00 0b d1 96 c8 49 00 00 f7 d5}  //weight: 10, accuracy: High
        $x_2_2 = "AAlBlPl4m" ascii //weight: 2
        $x_2_3 = "ClaqGzUkMK" ascii //weight: 2
        $x_2_4 = "DllRegisterServer" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_CM_2147816156_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.CM!MTB"
        threat_id = "2147816156"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "I?RStrTitle@dp_misc@@QAE?BVOUString@rtl@@XZ" ascii //weight: 1
        $x_1_2 = "I?4AbortChannel@dp_misc@@QAEAAV01@ABV01@@Z" ascii //weight: 1
        $x_1_3 = "I?_7AbortChannel@dp_misc@@6BXTypeProvider@lang@star@sun@com@@@" ascii //weight: 1
        $x_1_4 = "ITRACE@dp_misc@@YAXABVOString@rtl@@@Z" ascii //weight: 1
        $x_1_5 = "IcheckBlacklist@DescriptionInfoset@dp_misc@@ABEXXZ" ascii //weight: 1
        $x_1_6 = "IexpandUnoRcTerm@dp_misc@@YA?AVOUString@rtl@@ABV23@@Z" ascii //weight: 1
        $x_1_7 = "IgenerateRandomPipeId@dp_misc@@YA?AVOUString@rtl@@XZ" ascii //weight: 1
        $x_1_8 = "ImakeRcTerm@dp_misc@@YA?AVOUString@rtl@@ABV23@@Z" ascii //weight: 1
        $x_1_9 = "Ioffice_is_running@dp_misc@@YA_NXZ" ascii //weight: 1
        $x_1_10 = "IwriteConsole@dp_misc@@YAXABVOString@rtl@@@Z" ascii //weight: 1
        $x_1_11 = "IreadConsole@dp_misc@@YA?AVOUString@rtl@@XZ" ascii //weight: 1
        $x_1_12 = "Iplatform_fits@dp_misc@@YA_NABVOUString@rtl@@@Z" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_RPR_2147816396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.RPR!MTB"
        threat_id = "2147816396"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 8b 4d 0c 6b 11 03 52 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 dc 83 c2 01 89 55 dc 8b 45 f0 83 e8 01 39 45 dc 7d 1a 8b 4d c4 03 4d d4 8b 55 dc 8a 44 15 d8 88 01 8b 4d d4 83 c1 01 89 4d d4 eb d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_RPR_2147816396_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.RPR!MTB"
        threat_id = "2147816396"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AFd9rHM1a" ascii //weight: 1
        $x_1_2 = "BataM6ohoo" ascii //weight: 1
        $x_1_3 = "Axio9P5W" ascii //weight: 1
        $x_1_4 = "CNnEPx" ascii //weight: 1
        $x_1_5 = "CZxDQkV" ascii //weight: 1
        $x_1_6 = "DYcfCBxS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_RPA_2147818125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.RPA!MTB"
        threat_id = "2147818125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 d8 01 18 8b 45 c4 03 45 a8 03 45 ac 48 8b 55 d8 33 02 89 45 a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_RPD_2147818233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.RPD!MTB"
        threat_id = "2147818233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 d8 8b 45 d8 01 18 8b 45 d8 8b 00 8b 55 c4 03 55 a8 03 55 ac 4a 33 c2 89 45 a0 8b 45 d8 8b 55 a0 89 10 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_BM_2147822885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.BM!MTB"
        threat_id = "2147822885"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 d8 8b 45 d8 33 18 89 5d a0}  //weight: 2, accuracy: High
        $x_3_2 = {8b 45 a8 03 45 ac 48 89 45 a4 8b 45 a8 8b 55 d8 01 02}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_BM_2147822885_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.BM!MTB"
        threat_id = "2147822885"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllInstall" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "HiefplnBaydof" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_BM_2147822885_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.BM!MTB"
        threat_id = "2147822885"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "coenamourment" ascii //weight: 1
        $x_1_2 = "gianthood" ascii //weight: 1
        $x_1_3 = "hoaxer" ascii //weight: 1
        $x_1_4 = "supercargo" ascii //weight: 1
        $x_1_5 = "psoriatiform" ascii //weight: 1
        $x_1_6 = "unexplicitness" ascii //weight: 1
        $x_1_7 = "meconophagism" ascii //weight: 1
        $x_1_8 = "thurifer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_ER_2147831938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.ER!MTB"
        threat_id = "2147831938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 44 24 2c 66 8b 04 38 66 33 07 8d 7f 04 66 01 01 8b 44 24 48}  //weight: 3, accuracy: High
        $x_2_2 = {8a 4c 24 11 0f b6 c9 66 2b c8 8b 44 24 5c 66 89 0c 50}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_RPB_2147834564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.RPB!MTB"
        threat_id = "2147834564"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 04 24 8b 4c 24 ?? 8a 14 01 8b 74 24 ?? 88 14 06 83 c0 01 8b 7c 24 ?? 39 f8 89 04 24 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_RPB_2147834564_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.RPB!MTB"
        threat_id = "2147834564"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 55 ff 0f be 45 fe 83 c0 75 88 45 fe 0f be 4d fe 83 e9 17 88 4d fe 0f be 55 fe 83 ca 45 88 55 fe 0f b6 45 ff d1 f8 88 45 ff 0f b6 4d ff 81 f1 ff 00 00 00 88 4d ff 0f bf 55 dc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_RPB_2147834564_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.RPB!MTB"
        threat_id = "2147834564"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 12 03 15 ?? ?? ?? 00 03 c2 8b 15 ?? ?? ?? 00 89 02 a1 ?? ?? ?? 00 03 05 ?? ?? ?? 00 48 a3 ?? ?? ?? ?? ?? ?? ?? ?? 00 03 05 ?? ?? ?? 00 a3 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 83 c0 04 a3 ?? ?? ?? 00 33 c0 a3 ?? ?? ?? 00 a1 ?? ?? ?? 00 83 c0 04 03 05 ?? ?? ?? 00 a3 ?? ?? ?? 00 a1 ?? ?? ?? 00 3b 05 ?? ?? ?? 00 0f 82 59 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_A_2147835427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.A!MTB"
        threat_id = "2147835427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 45 dc 8b 45 dc 83 e8 04 89 45 dc 33 c0 89 45 b4 33 c0 89 45 b0 c7 45 c4 02 00 00 00 c7 45 bc 01 00 00 00 8b 45 e4 8b 10}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_RPM_2147835584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.RPM!MTB"
        threat_id = "2147835584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f af 87 94 00 00 00 89 87 94 00 00 00 8b 47 64 8b 4f 78 8b 1c 30 83 c6 04 0f af 5f 40 8b 47 50 8b d3 c1 ea 08 88 14 01 ff 47 50 8b 87 b8 00 00 00 8b 4f 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakBot_RPY_2147847030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakBot.RPY!MTB"
        threat_id = "2147847030"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 80 f4 00 00 00 03 86 a4 00 00 00 2b c3 50 8b 46 34 33 c5 50 8b 86 ac 00 00 00 0d 34 1e 00 00 0f af 46 78 56 50}  //weight: 1, accuracy: High
        $x_1_2 = {50 8b 46 64 33 44 24 2c 03 41 20 8d 8f 51 ff ff ff 50 69 c2 ?? ?? 00 00 50 8b c7 35 ?? ?? 00 00 05 ?? ?? 00 00 50 8b 86 ac 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

