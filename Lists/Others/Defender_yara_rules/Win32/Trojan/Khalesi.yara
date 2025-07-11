rule Trojan_Win32_Khalesi_RL_2147773162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Khalesi.RL!MTB"
        threat_id = "2147773162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 02 83 c8 20 0f b6 c8 33 4d ?? 89 4d ?? 8b 55 ?? 83 c2 01 89 55}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 04 8b 4d ?? 83 e1 01 8b 15 ?? ?? ?? ?? 0f af 8a ?? ?? ?? ?? 33 c1 89 45 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Khalesi_RW_2147798401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Khalesi.RW!MTB"
        threat_id = "2147798401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 04 00 00 00 c1 e0 00 8b 4d ?? 8b 14 01 89 55 ?? c7 45 ?? b9 79 37 9e 8b 45 ?? c1 e0 05 89 45 ?? c7 45 ?? 00 00 00 00 eb ?? 8b 4d ?? 83 c1 01 89 4d ?? 83 7d ?? 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Khalesi_RM_2147799400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Khalesi.RM!MTB"
        threat_id = "2147799400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 83 e2 03 03 c2 c1 f8 02 89 45 ?? 8b 4d ?? 81 c1 c6 04 00 00 89 4d ?? 8b 55 ?? 81 3a 72 f3 01 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Khalesi_CA_2147813501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Khalesi.CA!MTB"
        threat_id = "2147813501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 d9 31 3e 01 db 21 cb 81 c6 01 00 00 00 39 c6 75 e3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Khalesi_CB_2147816559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Khalesi.CB!MTB"
        threat_id = "2147816559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 18 01 f1 40 b9 [0-4] 01 f1 39 f8 75 d5}  //weight: 2, accuracy: Low
        $x_2_2 = {31 07 41 01 c9 81 c7 01 00 00 00 39 f7 75 e7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Khalesi_RDA_2147836066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Khalesi.RDA!MTB"
        threat_id = "2147836066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PEiD v0.95" ascii //weight: 1
        $x_1_2 = "Cheat Engine 6.7" ascii //weight: 1
        $x_1_3 = "WinDbgFrameClass" ascii //weight: 1
        $x_1_4 = "ImmunityDebugger.exe" ascii //weight: 1
        $x_1_5 = "joeboxcontrol.exe" ascii //weight: 1
        $x_1_6 = "joeboxserver.exe" ascii //weight: 1
        $x_1_7 = "open %s type cdaudio alias cd wait shareable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Khalesi_MA_2147836280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Khalesi.MA!MTB"
        threat_id = "2147836280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 30 d0 38 96 ?? ?? ?? ?? a6 a1}  //weight: 1, accuracy: Low
        $x_1_2 = {02 f8 69 1e ?? ?? ?? ?? 48 0f 00 ff cc 31 [0-12] 9b 96 f1 ba ?? ?? ?? ?? 81 ff ?? ?? ?? ?? f0 47 9f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Khalesi_MA_2147836280_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Khalesi.MA!MTB"
        threat_id = "2147836280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {68 88 ee 4a 00 6a 40 6a 04 68 d8 97 49 00 ff 15 18 93 49 00 0f b6 05 d0 97 49 00 a2 cc 97 49 00 0f b6 05 d1 97 49 00 68 88 ee 4a 00 ff 35 88 ee 4a 00 a2 cd 97 49 00 0f b6 05 d2 97 49 00 a2 ce 97 49 00 0f b6 05 d3 97 49 00 6a 04 68 d8 97 49 00 a2 cf 97 49}  //weight: 10, accuracy: High
        $x_1_2 = "/force" ascii //weight: 1
        $x_1_3 = "SetDefaultMouseSpeed" ascii //weight: 1
        $x_1_4 = "PostMessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Khalesi_ARA_2147837756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Khalesi.ARA!MTB"
        threat_id = "2147837756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ollydbg.exe" ascii //weight: 1
        $x_1_2 = "procmon.exe" ascii //weight: 1
        $x_1_3 = "ImmunityDebugger.exe" ascii //weight: 1
        $x_1_4 = "sniff_hit.exe" ascii //weight: 1
        $x_1_5 = "windbg.exe" ascii //weight: 1
        $x_1_6 = "joeboxcontrol.exe" ascii //weight: 1
        $x_1_7 = "Vmwaretrat.exe" ascii //weight: 1
        $x_1_8 = "vboxservice.exe" ascii //weight: 1
        $x_1_9 = "taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1" ascii //weight: 1
        $x_1_10 = "taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1" ascii //weight: 1
        $x_1_11 = "taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1" ascii //weight: 1
        $x_1_12 = "taskkill /FI \"IMAGENAME eq fiddler*\" /IM * /F /T >nul 2>&1" ascii //weight: 1
        $x_1_13 = "taskkill /FI \"IMAGENAME eq wireshark*\" /IM * /F /T >nul 2>&1" ascii //weight: 1
        $x_1_14 = "taskkill /FI \"IMAGENAME eq ida*\" /IM * /F /T >nul 2>&1" ascii //weight: 1
        $x_1_15 = "sc stop npf >nul 2>&1" ascii //weight: 1
        $x_2_16 = "discord.gg/d6RGMKCrj6" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Khalesi_AP_2147839635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Khalesi.AP!MTB"
        threat_id = "2147839635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {93 54 d0 1e 6c b8 8f 84 6d c8 01 82 73 07 0c c5 43 8a a7 d6 ae 04 0c 01 ee 33 aa 2d b2 7f 2e 6c c8 a5 e6 28 24 d8 54 96 d1 29 b8 ce 4e b5 b8 09 08 fd b8 7e 38 db b1 01 17 54 75}  //weight: 1, accuracy: High
        $x_1_2 = {0e 48 0b 76 af 8a 32 c9 21 fa 47 30 9c f1 3c 72 c2 2f e7 d3 96 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Khalesi_GHA_2147843670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Khalesi.GHA!MTB"
        threat_id = "2147843670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 17 89 c3 81 c7 ?? ?? ?? ?? 48 39 f7 75 ec 81 e8 ?? ?? ?? ?? 21 c9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Khalesi_DAL_2147851322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Khalesi.DAL!MTB"
        threat_id = "2147851322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3e 42 4c bd 8c 3e 36 20 31 8e 9e 8c a9 83 1c 4f 0c 0d 4b b2 fd 47 6b 01 cb 61 f1 6e 68 4e b2 cb 39 e6 4f 95 8d 6e 9d b8 f2 8a 43 9d c5 49 ee 9b 78}  //weight: 1, accuracy: High
        $x_1_2 = {bb f0 70 5e c4 b4 1b 36 ed 3c 4f 68 5d ba 95 49 b4 83 13 c0 25 b0 d3 81 8a 34 68 4b 57 7f}  //weight: 1, accuracy: High
        $x_1_3 = {32 b3 75 6a 3f 3f 02 2c 2c 2c 23 89 bf 3e 88 1d b2 0f a9 98 37 22 56 a8 e6 e6 f9 32 3f}  //weight: 1, accuracy: High
        $x_1_4 = {4c 2b 86 79 94 d4 da 31 6a 91 02 02 02 02 02 53 53 92 c2 52 85 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Khalesi_CCDW_2147896340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Khalesi.CCDW!MTB"
        threat_id = "2147896340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 17 29 ce 81 c7 ?? ?? ?? ?? 39 c7 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Khalesi_RPX_2147898668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Khalesi.RPX!MTB"
        threat_id = "2147898668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {59 31 32 42 89 cf 01 cf 39 c2 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Khalesi_GAN_2147899902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Khalesi.GAN!MTB"
        threat_id = "2147899902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {01 d3 31 39 89 d2 21 d3 81 c1 01 00 00 00 39 f1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Khalesi_GMA_2147900266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Khalesi.GMA!MTB"
        threat_id = "2147900266"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {29 fb 47 31 31 52 5b 81 c1 04 00 00 00 39 c1}  //weight: 10, accuracy: High
        $x_10_2 = {31 16 81 c6 04 00 00 00 4b 57 59 39 c6}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Khalesi_GZZ_2147901847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Khalesi.GZZ!MTB"
        threat_id = "2147901847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 c0 c7 04 24 02 00 00 00 c7 44 24 ?? 2c 02 00 00 e8 ?? ?? ?? ?? 51 89 c3 51 8d 74 24 ?? 89 04 24 89 74 24 ?? e8 ?? ?? ?? ?? 52 52 85 c0 75 ?? 31 c0 eb ?? 89 74 24 ?? 89 1c 24 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Khalesi_EC_2147903131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Khalesi.EC!MTB"
        threat_id = "2147903131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {df 42 ea 31 38 81 c0 04 00 00 00 39 d0 75 ef 41 01 de c3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Khalesi_HNS_2147905839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Khalesi.HNS!MTB"
        threat_id = "2147905839"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3b 45 0c 74 0f 89 c3 83 e3 ?? 8a 5c 1d ?? 30 1c 02 40 eb}  //weight: 2, accuracy: Low
        $x_1_2 = {0f b6 44 7e ?? c1 e3 ?? 89 04 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Khalesi_HNA_2147908322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Khalesi.HNA!MTB"
        threat_id = "2147908322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 01 ea 31 01 81 c1 04 00 00 00 29 f2}  //weight: 1, accuracy: High
        $x_1_2 = {8b 0c 24 83 c4 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Khalesi_PGK_2147946038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Khalesi.PGK!MTB"
        threat_id = "2147946038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2e 74 65 78 74 00 00 00 c0 78 00 00 00 10 00 00 00 7a 00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 e0}  //weight: 5, accuracy: High
        $x_5_2 = {2e 74 65 78 74 00 00 00 00 20 00 00 00 90 0a 00 00 14 00 00 00 30 04 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 42}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

