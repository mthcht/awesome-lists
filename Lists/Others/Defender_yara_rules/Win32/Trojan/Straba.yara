rule Trojan_Win32_Straba_EH_2147832746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Straba.EH!MTB"
        threat_id = "2147832746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Straba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 20 eb 0a a1 ?? ?? ?? ?? 83 c0 20 ff d0 8d 05 ?? ?? ?? ?? 89 18 89 f0 01 05 ?? ?? ?? ?? 89 ea 89 15 ?? ?? ?? ?? 01 3d ?? ?? ?? ?? eb d6 c3 89 45}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Straba_EH_2147832746_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Straba.EH!MTB"
        threat_id = "2147832746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Straba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "greenAmovethOurheAformgrass" wide //weight: 1
        $x_1_2 = "8MovingcreepethmayE" wide //weight: 1
        $x_1_3 = "0tmayKsaying" wide //weight: 1
        $x_1_4 = "maletheirweq" wide //weight: 1
        $x_1_5 = "qtreeGSiwas" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Straba_EH_2147832746_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Straba.EH!MTB"
        threat_id = "2147832746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Straba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FfillcbeholdEyou.reitselfj" wide //weight: 1
        $x_1_2 = "placeGmeatWVT" wide //weight: 1
        $x_1_3 = "gAlifeVvfacecreepingU" wide //weight: 1
        $x_1_4 = "qdrymeatgreenntseasons" wide //weight: 1
        $x_1_5 = "Lightblessedhis2b" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Straba_MA_2147832768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Straba.MA!MTB"
        threat_id = "2147832768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Straba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DRCFVTGY.DLL" ascii //weight: 3
        $x_3_2 = "RdrfvtKhbg" ascii //weight: 3
        $x_3_3 = "OjmnTtgb" ascii //weight: 3
        $x_3_4 = "RsWsd" ascii //weight: 3
        $x_1_5 = "GetCurrentThreadId" ascii //weight: 1
        $x_1_6 = "GetTempPathW" ascii //weight: 1
        $x_1_7 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Straba_NE_2147832889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Straba.NE!MTB"
        threat_id = "2147832889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Straba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "IbvyExdvg" ascii //weight: 5
        $x_5_2 = "IbhugvyRyvgh" ascii //weight: 5
        $x_5_3 = "OibhRtcf" ascii //weight: 5
        $x_1_4 = "GetCurrentProcessId" ascii //weight: 1
        $x_1_5 = "GetSystemTimeAsFileTime" ascii //weight: 1
        $x_1_6 = "GetCurrentThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Straba_NEA_2147832943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Straba.NEA!MTB"
        threat_id = "2147832943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Straba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 54 52 56 59 55 42 59 2e 44 4c 4c 00 49 62 76 79 45 78 64 76 67 00 4f 69 62 68 52 74 63 66 00 49 62 68 75 67 76 79 52 79 76 67 68}  //weight: 1, accuracy: High
        $x_1_2 = {54 52 43 41 47 55 42 2e 44 4c 4c 00 48 76 67 66 63 44 62 68 6e 00 4f 68 62 67 44 63 74 66 00 4a 62 68 75 67 44 66 76 79 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Straba_AST_2147832990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Straba.AST!MTB"
        threat_id = "2147832990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Straba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "IgvYbyn" ascii //weight: 5
        $x_5_2 = "OnbFtvyb" ascii //weight: 5
        $x_1_3 = "GetCurrentThreadId" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Straba_RA_2147833187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Straba.RA!MTB"
        threat_id = "2147833187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Straba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 09 89 ca 88 d3 ba 01 00 00 00 81 e9 b8 00 00 00 89 d6 89 85 ?? fe ff ff 89 95 ?? fe ff ff 88 9d ?? fe ff ff 89 8d ?? fe ff ff 89 b5 ?? fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Straba_RB_2147833188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Straba.RB!MTB"
        threat_id = "2147833188"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Straba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 08 88 8d ?? fe ff ff b8 01 00 00 00 b9 01 00 00 00 8a 95 ?? fe ff ff 0f b6 f2 81 ee b8 00 00 00 89 cf 89 85 ?? fe ff ff 89 8d ?? fe ff ff 89 b5 ?? fe ff ff 89 bd ?? fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Straba_RO_2147833203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Straba.RO!MTB"
        threat_id = "2147833203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Straba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 75 e8 8a 1c 06 0f b6 fb 01 cf 89 45 dc 31 c9 89 55 d8 89 ca 8b 4d f0 f7 f1 8b 4d ec 0f b6 14 11 01 d7 89 f8 99 8b 7d d8 f7 ff 8a 3c 16 8b 4d dc 88 3c 0e 88 1c 16}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Straba_EB_2147833353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Straba.EB!MTB"
        threat_id = "2147833353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Straba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FGBHNJMK.DLL" ascii //weight: 1
        $x_1_2 = "FfgbHgybh" ascii //weight: 1
        $x_1_3 = "FgbyhnKjgv" ascii //weight: 1
        $x_1_4 = "TtfvygbKhbgf" ascii //weight: 1
        $x_1_5 = "GetCurrentThreadId" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Straba_EB_2147833353_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Straba.EB!MTB"
        threat_id = "2147833353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Straba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Self.exe" ascii //weight: 1
        $x_1_2 = "MVYsfirstcreepeth" ascii //weight: 1
        $x_1_3 = "You.llnfacevErdryjwhalestheir" ascii //weight: 1
        $x_1_4 = "I3zElifeheavenw" ascii //weight: 1
        $x_1_5 = "seaI0Qis" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

