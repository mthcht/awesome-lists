rule Trojan_Win32_Cobaltstrike_DK_2147759716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.DK!MTB"
        threat_id = "2147759716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 8d 94 01 ?? ?? ?? ?? 8b 45 08 03 10 8b 4d 08 89 11 68 5a 11 00 00 ff 15 ?? ?? ?? ?? 05 9c 5b 00 00 8b 55 08 8b 0a 2b c8 8b 55 08 89 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_MK_2147761004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.MK!MTB"
        threat_id = "2147761004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a1 fc fe 54 00 33 c1 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 00 8b ff a1 ?? ?? ?? ?? 8b 0d 00 89 08 5f 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_MK_2147761004_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.MK!MTB"
        threat_id = "2147761004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c5 04 0f af 5f 30 8b 87 ?? ?? ?? ?? 8b d3 c1 ea 10 88 14 01 8b d3 ff 47 38 8b 8f ?? ?? ?? ?? 8b 47 3c 81 c1 ?? ?? ?? ?? 03 c1 c1 ea 08}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_MK_2147761004_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.MK!MTB"
        threat_id = "2147761004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 48 02 c1 e1 ?? 33 f9 0f b6 48 01 c1 e1 ?? 33 f9 0f b6 00 33 c7 69 f8 ?? ?? ?? ?? 8b c7 c1 e8 ?? 33 c7 69 c8 02 5f 5e 8b c1 c1 e8 ?? 33 c1 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_MB_2147762275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.MB!MTB"
        threat_id = "2147762275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 86 80 00 00 00 8b 86 b4 00 00 00 8b d3 c1 ea 08 88 14 01 ff 86 9c 00 00 00 8b 8e 9c 00 00 00 8b 86 b4 00 00 00 88 1c 01 ff 86 9c 00 00 00 8b 86 ec 00 00 00 8b 96 88 00 00 00 2b c2 01 46 1c 81 fd e8 94 01 00 0f 8c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_AA_2147762711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.AA!MTB"
        threat_id = "2147762711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InDefiniteQ" ascii //weight: 1
        $x_1_2 = "vvsection" ascii //weight: 1
        $x_1_3 = "no such device or address" ascii //weight: 1
        $x_1_4 = "FlushProcessWriteBuffers" ascii //weight: 1
        $x_1_5 = "indefinite86.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_SM_2147773501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.SM!MSR"
        threat_id = "2147773501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f ef c2 0f 11 80 ?? ?? ?? ?? 0f 10 80 ?? ?? ?? ?? 66 0f ef c8 0f 11 88 ?? ?? ?? ?? 83 c0 40 3d 40 03 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_MFP_2147782173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.MFP!MTB"
        threat_id = "2147782173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c0 33 c9 0f a2 44 8b c1 45 33 db 44 8b cb 41 81 f0 6e 74 65 6c 41 81 f1 47 65 6e 75 44 8b d2 8b f0 33 c9 41 8d ?? ?? 45 0b c8 0f a2 41 81 f2}  //weight: 5, accuracy: Low
        $x_5_2 = {66 0f 6e c3 8b fb f3 0f e6 c0 be 02 ?? ?? ?? e8 ?? ?? ?? ?? 66 0f 2f 05 ?? ?? ?? ?? 72 ?? 8b c7 99 f7 fe 85 d2 0f 45 c7 ff c6 8b f8 66 0f 6e c0 f3 0f e6 c0 66 0f 6e f6 f3 0f e6 f6 e8 66 66 01 00 66 0f 2f c6 73 ?? ff c3 81 fb 7f 84 1e 00 7c}  //weight: 5, accuracy: Low
        $x_5_3 = {0f 10 03 0f 11 01 0f 10 4b 10 0f 11 49 10 0f 10 43 20 0f 11 41 20 0f 10 4b 30 0f 11 49 30 0f 10 43 40 0f 11 41 40 0f 10 4b 50 0f 11 49 50 0f 10 43 60 0f 11 41 60 48 03 cd 0f 10 4b 70 48 03 dd 0f 11 49 f0 48 83 ef 01 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Cobaltstrike_MKRT_2147794083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.MKRT!MTB"
        threat_id = "2147794083"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c8 c1 e8 12 24 07 0c f0 88 02 89 c8 c1 e8 0c 24 3f 0c 80 88 42 01 89 c8 c1 e8 06 24 3f 0c 80 88 42 02 80 e1 3f 80 c9 80 88 4a 03 b9 04 00 00 00 48 81 c4 98}  //weight: 1, accuracy: High
        $x_1_2 = "Local\\RustBacktraceMutex" ascii //weight: 1
        $x_1_3 = "rust_eh_personality" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_DC_2147794111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.DC!MTB"
        threat_id = "2147794111"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\spy\\cobaltstrike-client" ascii //weight: 1
        $x_1_2 = "gigabigsvc" ascii //weight: 1
        $x_1_3 = "CreatePipe" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "ServiceMain" ascii //weight: 1
        $x_1_6 = "SetEndOfFile" ascii //weight: 1
        $x_1_7 = "CryptEncrypt" ascii //weight: 1
        $x_1_8 = "CreateMutexA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_DD_2147798234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.DD!MTB"
        threat_id = "2147798234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c6 83 ec 10 31 c0 39 d8 7d ?? 8b 4d 10 89 c2 83 e2 03 8a 14 11 8b 4d 08 32 14 01 88 14 06 40 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_DE_2147798235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.DE!MTB"
        threat_id = "2147798235"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 89 c1 03 4d 08 8b 45 f4 03 45 08 0f b6 18 8b 45 f4 89 c2 c1 fa 1f c1 ea ?? 01 d0 83 e0 ?? 29 d0 03 45 10 0f b6 00 31 d8 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_DF_2147798701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.DF!MTB"
        threat_id = "2147798701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4b 04 8b c9 8b c7 8b 55 0c 8b c0 c1 e1 02 2b c1 8a 04 10 32 06 88 04 3a 8b c9 8b c7 8b 4b 04 c1 e1 02 8b c9 2b c1 8a 44 10 01 8b c0 32 46 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_DF_2147798701_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.DF!MTB"
        threat_id = "2147798701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 07 89 7d f8 8b 7d fc 88 04 3e 8b c7 8b 7d f8 88 0c 07 0f b6 04 06 8b 4d fc 03 c2 8b 7d f4 0f b6 c0 8a 04 08 32 04 1f 88 03 43 83 6d 0c 01 8b c1 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_ROX_2147811089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.ROX!MTB"
        threat_id = "2147811089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ServerComputer" ascii //weight: 1
        $x_1_2 = "GetAsyncKeyState" ascii //weight: 1
        $x_1_3 = "NetworkStream" ascii //weight: 1
        $x_1_4 = "IAsyncResult" ascii //weight: 1
        $x_1_5 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_6 = "ContainsKey" ascii //weight: 1
        $x_1_7 = "WriteAllText" ascii //weight: 1
        $x_1_8 = "StrReverse" ascii //weight: 1
        $x_1_9 = "FromBase64CharArray" ascii //weight: 1
        $x_1_10 = "Loaded settings from registry" ascii //weight: 1
        $x_1_11 = "$fe53e141-8812-490f-ae7a-5627a794092e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_SMLL_2147817424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.SMLL!MTB"
        threat_id = "2147817424"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b d2 0a 8b c0 0f b6 08 83 e9 30 40 03 d1 80 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_UIP_2147818082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.UIP!MTB"
        threat_id = "2147818082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8b c3 44 88 1a 41 ff c3 83 e0 03 49 83 c0 04 48 ff c2 45 3b d9 0f b6 04 08 41 89 40 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_APS_2147819228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.APS!MTB"
        threat_id = "2147819228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 39 18 75 51 bb ?? ?? ?? ?? 66 39 58 02 75 46 bb ?? ?? ?? ?? 66 39 58 04 75 3b bb ?? ?? ?? ?? 66 39 58 06 75 30 bb ?? ?? ?? ?? 66 39 58 08 75 25 bb ?? ?? ?? ?? 66 39 58 0a 75 1a bb 73 73 00 00 66 39 58 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_VA_2147819229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.VA!MTB"
        threat_id = "2147819229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 10 50 52 8b 54 24 10 52 8b 54 24 10 52 8b 0d 4c 30 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_EF_2147823613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.EF!MTB"
        threat_id = "2147823613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 02 6a 00 e8 ?? ?? ?? ?? 8b 5d d8 03 5d b0 03 5d e8 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 89 5d b4 8b 45 b4 8b 55 ec 31 02 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_EG_2147826285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.EG!MTB"
        threat_id = "2147826285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 44 24 ?? 48 63 54 24 ?? 0f be 0c 10 8b 44 24 ?? 41 b9 ?? ?? ?? ?? 99 41 f7 f9 83 c2 ?? 31 d1 48 63 44 24 ?? 41 88 0c 00 8b 44 24 ?? 83 c0 01 89 44 24 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_EH_2147827769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.EH!MTB"
        threat_id = "2147827769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 02 8b 45 d8 03 45 b0 03 45 e8 89 45 b4}  //weight: 1, accuracy: High
        $x_1_2 = {03 d8 8b 45 ec 31 18 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_EI_2147828054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.EI!MTB"
        threat_id = "2147828054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 d8 8b 45 ec 89 18 8b 45 d8 03 45 b0 03 45 e8 89 45 b4 8b 45 b4 8b 55 ec 31 02 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_EJ_2147828202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.EJ!MTB"
        threat_id = "2147828202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 f7 eb c1 fa ?? 41 89 d2 44 89 c0 c1 f8 ?? 41 29 c2 44 89 d0 c1 e0 ?? 42 8d 04 50 44 89 c2 29 c2 48 63 d2 48 8b 0d ?? ?? ?? ?? 0f b6 14 11 42 32 94 04 ?? ?? ?? ?? 43 88 14 01}  //weight: 1, accuracy: Low
        $x_1_2 = {41 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 c1 e0 ?? 8d 14 50 41 29 d1 4d 63 c9 48 8b 05 ?? ?? ?? ?? 42 0f b6 04 08 32 44 0c ?? 41 88 04 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Cobaltstrike_EK_2147828954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.EK!MTB"
        threat_id = "2147828954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 02 8b 45 c4 03 45 a4 03 45 9c 2b 45 9c 89 45 a0 8b 45 d8 8b 00 8b 55 a0 03 55 9c 2b 55 9c 33 c2 89 45 a0 8b 45 a0 03 45 9c 2b 45 9c 8b 55 d8 89 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_FG_2147832375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.FG!MTB"
        threat_id = "2147832375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 33 d2 f7 75 0c 8b 45 08 0f be 14 10 33 ca 8b 45 10 03 45 fc 88 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_RPP_2147837292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.RPP!MTB"
        threat_id = "2147837292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {29 c1 89 c8 0f af 45 e4 01 d0 89 c2 8b 45 d8 01 d0 0f b6 00 31 f0 88 03 83 45 e0 01 83 45 e4 01 8b 45 e0 3b 45 0c 0f 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_RPT_2147838987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.RPT!MTB"
        threat_id = "2147838987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 70 29 c6 c6 00 e9 83 ee 05 89 70 01 8b 44 24 78 8b 74 24 1c 89 30 8b 44 24 30 89 5c 24 0c 89 44 24 08 8b 44 24 70 c7 44 24 04 05 00 00 00 89 04 24 8b 44 24 18 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_SB_2147839735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.SB!MTB"
        threat_id = "2147839735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 1c 01 ff 46 ?? 8b 86 ?? ?? ?? ?? 03 46 ?? 35 ?? ?? ?? ?? 29 46 ?? 8b 86 ?? ?? ?? ?? 01 46 ?? 8b 46 ?? 31 46 ?? b8 ?? ?? ?? ?? 2b 86 ?? ?? ?? ?? 2b 86 ?? ?? ?? ?? 01 46 ?? 8b 86}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_RPR_2147840901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.RPR!MTB"
        threat_id = "2147840901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 d2 8d 76 00 0f b6 04 0a 88 04 1a 42 84 c0 75 f4 8b 35 28 80 40 00 85 f6 87 d0 c1 c9 03 33 c7 c1 cb 17 2b d4 03 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_RPZ_2147844737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.RPZ!MTB"
        threat_id = "2147844737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 44 3c 18 8a cb 88 44 24 19 88 4c 3c 18 8a 5c 24 19 0f b6 c1 0f b6 fb 03 c7 0f b6 c0 0f b6 44 04 18 30 84 34 18 02 00 00 0f b6 84 34 18 02 00 00 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_RPY_2147848252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.RPY!MTB"
        threat_id = "2147848252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 e0 31 f6 89 75 e0 89 44 24 0c c7 44 24 08 40 00 00 00 89 5c 24 04 8b 45 08 89 04 24 a1 ?? ?? ?? ?? 89 45 d4 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_RPX_2147898621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.RPX!MTB"
        threat_id = "2147898621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 8d 45 f8 50 ff 36 ff d3 3d ?? ?? ?? ?? 74 2c 83 c6 04 83 c7 06 81 fe ?? ?? ?? ?? 7c e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_GPA_2147900404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.GPA!MTB"
        threat_id = "2147900404"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {83 c4 04 89 45 e8 33 d2 85 db 74 26 8b 75 e0 8b f8 90 8b c2 8b ca c1 e8 02 83 e1 03 c1 e1 03 8b 04 86 d3 e8 88 04 3a 42 3b d3}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_AMBE_2147903002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.AMBE!MTB"
        threat_id = "2147903002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "No dbg was detected running shellcode" ascii //weight: 1
        $x_1_2 = "remote dbg is running" ascii //weight: 1
        $x_1_3 = "local dbg is running" ascii //weight: 1
        $x_1_4 = "dbg is disabled" ascii //weight: 1
        $x_1_5 = "KDB: Disabled" ascii //weight: 1
        $x_1_6 = "Bypass_AV.pdb" ascii //weight: 1
        $x_1_7 = "[+] Byte 0x%X wrote sucessfully! at 0x" ascii //weight: 1
        $x_1_8 = "[+] process opened - Handle value is" ascii //weight: 1
        $x_1_9 = "[+] The thread finished!" ascii //weight: 1
        $x_1_10 = "[+] Running the thread" ascii //weight: 1
        $x_1_11 = "[+] Memory Allocated" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_HD_2147903125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.HD!MTB"
        threat_id = "2147903125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {43 3a 5c 55 73 65 72 73 5c 61 64 6d 69 6e 5c 44 65 73 6b 74 6f 70 [0-10] 5c 43 6c 65 61 6e 55 70 5c 52 65 6c 65 61 73 65 5c 43 6c 65 61 6e 55 70 2e 70 64 62}  //weight: 10, accuracy: Low
        $x_1_2 = {43 6c 65 61 6e 55 70 2e 64 6c 6c 00 43 6c 65 61 6e 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_HE_2147903826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.HE!MTB"
        threat_id = "2147903826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {39 c6 7e 17 48 89 c2 83 e2 07 41 8a 14 16 41 32 54 05 00 88 14 03 48 ff c0 eb e5}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_HI_2147907429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.HI!MTB"
        threat_id = "2147907429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\Public\\Documents\\s1.dll" ascii //weight: 1
        $x_1_2 = "fail running step2" ascii //weight: 1
        $x_1_3 = "Decompress failed: %d" ascii //weight: 1
        $x_1_4 = "CreateFile failed: %d" ascii //weight: 1
        $x_1_5 = "NtDCompositionDestroyChannel" ascii //weight: 1
        $x_1_6 = "RtlDecompressBuffer" ascii //weight: 1
        $x_1_7 = "D3D11CreateDevice" ascii //weight: 1
        $x_1_8 = {54 68 69 73 20 70 72 00 6f 67 72 61 6d 20 63 61 00 6e 6e 6f 74 20 62 65 20 00 72 75 6e 20 69 6e 20 44 00 4f 53 20 6d 6f 64 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobaltstrike_AJS_2147924457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobaltstrike.AJS!MTB"
        threat_id = "2147924457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 c9 03 ca 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 0f b6 4c 0c 0c 30 0c 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

