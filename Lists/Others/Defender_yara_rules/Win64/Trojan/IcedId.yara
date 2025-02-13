rule Trojan_Win64_IcedId_PY_2147783595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.PY!MTB"
        threat_id = "2147783595"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ce 48 8d 15 ?? ?? ?? ?? 8a 0a 88 4c ?? ?? 80 44 [0-4] c0 64 [0-4] 8a 4c [0-2] 88 4c [0-2] 8a 4a 01 88 4c [0-2] 80 44 [0-4] 8a 4c [0-2] 08 4c [0-2] 8a 4c [0-2] 30 4c [0-2] fe 44 [0-2] 8a 4c [0-2] 88 0c 38 39 fe 74 [0-2] 48 ff c7 48 83 c2 [0-2] eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_AMT_2147787039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.AMT!MTB"
        threat_id = "2147787039"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 81 ec 38 01 00 00 bb 10 80 27 00 48 8d 74 24 20 89 1e 89 5c 24 28 f2 0f 2a 44 24 28 48 8d 7c 24 30 f2 0f 11 07}  //weight: 10, accuracy: High
        $x_10_2 = {48 81 ec 58 01 00 00 be b7 c1 27 00 89 74 24 2c 89 74 24 28 f2 0f 2a 44 24 28 f2 0f 11 44 24 30 89 74 24 2c 89 74 24 28 0f 57 c0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_AMT_2147787039_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.AMT!MTB"
        threat_id = "2147787039"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "hoperd" ascii //weight: 3
        $x_3_2 = "kompw" ascii //weight: 3
        $x_3_3 = "paramt" ascii //weight: 3
        $x_3_4 = "SendMessageA" ascii //weight: 3
        $x_3_5 = "GetMessageW" ascii //weight: 3
        $x_3_6 = "DispatchMessageW" ascii //weight: 3
        $x_3_7 = "SystemParametersInfoW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_SIBC_2147787622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.SIBC!MTB"
        threat_id = "2147787622"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 85 c9 74 ?? 44 8a 11 45 84 d2 74 ?? ff ca 31 c0 41 b9 ?? ?? ?? ?? 45 8d 5a ?? 41 0f b6 fa 41 80 c2 ?? 41 0f b6 f2 45 84 c0 0f 44 f7 41 80 fb ?? 0f 43 f7 89 c7 c1 c7 ?? 40 0f be c6 31 f8 44 39 ca 72 ?? 46 8a 14 09 49 ff c1 45 84 d2 75 ?? 35 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 46 ff c7 46 ?? ?? ?? ?? ?? 66 c7 46 ?? ?? ?? b8 ?? ?? ?? ?? 80 74 04 ?? ?? 48 ff c0 48 83 f8 ?? 75 ?? c6 44 24 ?? 00 31 c9 ba ?? ?? ?? ?? 41 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 f1 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_SIBE_2147787691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.SIBE!MTB"
        threat_id = "2147787691"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 0a 48 01 0e 48 8b 0e 8b 09 41 89 09 41 8b 09 41 8b 3a 44 31 f7 39 f9 48 89 45 ?? 4c 89 6d ?? 4c 89 5d ?? 65 48 8b 0c 25 60 00 00 00 48 8b 49 18 48 8b 41 ?? 48 85 c0 0f 84 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 51 ?? 0f af d1 f6 c2 ?? 0f 94 c1 83 3d ?? ?? ?? ?? ?? 0f 9c c2 08 ca 88 55 ?? 41 bd ?? ?? ?? ?? 48 8b 58 50 48 89 45 ?? 0f b7 70 48 31 d2 41 8a 0c 24 c1 c2 ?? 41 8a 0c 24 8a 0b 41 8a 04 24 41 88 0c 24 41 8a 04 24 41 0f b6 04 24 48 8d 3c 10 80 f9 ?? 48 8d 54 10 ?? 48 0f 46 d7 41 8a 04 24 48 ff c3 66 ff ce 75 ?? 41 8b 07 44 31 e8 39 d0 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8b 58 20 49 63 43 3c 41 8b 84 03 88 00 00 00 42 8b 54 18 20 42 8b 74 18 24 4c 01 da 4c 01 de 66 41 be ?? ?? 8b 0a 4c 01 d9 48 ff c1 8a 59 ?? 45 31 d2 44 89 d7 c1 c7 ?? 44 0f be d3 41 01 fa 8a 19 48 ff c1 84 db 75 ?? 41 8b 08 44 31 e9 41 39 ca 74 ?? 48 8b 4d ?? 8b 09 44 31 e9 41 39 ca 74 ?? 48 8b 4d ?? 8b 09 44 31 e9 41 39 ca 74 ?? 48 8b 4d ?? 8b 09 44 31 e9 41 39 ca 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_QW_2147794961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.QW!MTB"
        threat_id = "2147794961"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "WavTipSample.pdb" ascii //weight: 3
        $x_3_2 = "PathFindExtensionA" ascii //weight: 3
        $x_3_3 = "ShellExecuteA" ascii //weight: 3
        $x_3_4 = "WavTipSample.dll" ascii //weight: 3
        $x_3_5 = "ResumeServer" ascii //weight: 3
        $x_3_6 = "StartServer" ascii //weight: 3
        $x_3_7 = "StopServer" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_FA_2147796833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.FA!MTB"
        threat_id = "2147796833"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8a 09 4d 8d 49 02 88 4c 24 30 8a 4c 24 30 83 e9 25 88 4c 24 30 8a 44 24 30 c0 e0 04 88 44 24 30 8a 44 24 30 88 44 24 38 41 8a 41 ff 88 44 24 30 8a 44 24 30 83 e8 38 88 44 24 30 0f b6 44 24 38 8a 4c 24 30 0b c8 88 4c 24 38 0f b6 44 24 38 8a 4c 24 40 33 c8 88 4c 24 38 8a 44 24 40 fe c0 88 44 24 40 8a 44 24 38 41 88 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_FA_2147796833_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.FA!MTB"
        threat_id = "2147796833"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "t8yooZ" ascii //weight: 1
        $x_1_2 = "vKiFy0" ascii //weight: 1
        $x_1_3 = "wxlyiBhpW" ascii //weight: 1
        $x_1_4 = "xSskMGy" ascii //weight: 1
        $x_1_5 = "ygasbfgtfhjaskfyas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_FA_2147796833_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.FA!MTB"
        threat_id = "2147796833"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hwQiRMhcSPN" ascii //weight: 1
        $x_1_2 = "m2kVKYFBOav95aPl" ascii //weight: 1
        $x_1_3 = "mdEQi2p3" ascii //weight: 1
        $x_1_4 = "mfldK756s5l9Jt" ascii //weight: 1
        $x_1_5 = "nuyhafjshygfasfjasyjas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_SIBM_2147815125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.SIBM!MTB"
        threat_id = "2147815125"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be ca 41 0f be c0 0f af c8 41 0f be c0 0f be d1 0f af d0 8b c5 41 00 11 33 d2 41 f7 f2 0f be c8 44 0f be c0 41 8b 43 ?? 99 44 0f af c1 41 f7 fa 83 fb ?? 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be ca 41 8d 5a ?? 41 0f be c0 0f af c8 41 0f be c0 0f be d1 0f af d0 8b c5 41 00 51 01 33 d2 f7 f3 0f be c8 44 0f be c0 41 8b 03 99 44 0f af c1 f7 fb 41 83 fa ?? 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {0f be ca 41 8d 72 ?? 41 0f be c0 0f af c8 41 0f be c0 0f be d1 0f af d0 8b c5 41 00 51 02 33 d2 f7 f6 0f be c8 44 0f be c0 41 8b 43 ?? 99 44 0f af c1 f7 fe 83 fb ?? 7c}  //weight: 1, accuracy: Low
        $x_1_4 = {0f be ca 41 8d 5a ?? 41 0f be c0 0f af c8 41 0f be c0 0f be d1 0f af d0 8b c5 41 00 51 03 33 d2 f7 f3 0f be c8 44 0f be c0 41 8b 43 ?? 99 44 0f af c1 f7 fb 83 fe ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win64_IcedId_SIBN_2147816497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.SIBN!MTB"
        threat_id = "2147816497"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8d 46 ff 48 8d 15 ?? ?? ?? ?? 31 f6 8a 0a 88 0f 80 07 ?? c0 27 ?? 8a 0f 88 0b 8a 4a 01 88 0f 80 07 ?? 8a 0f 08 0b 41 8a 0e 30 0b 41 fe 06 8a 0b 88 0c 30 41 39 f0 74 ?? 48 ff c6 48 83 c2}  //weight: 1, accuracy: Low
        $x_1_2 = {31 ed 89 ef c1 c7 ?? 0f be eb 01 fd 8a 1e 48 ff c6 84 db 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_MG_2147818640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.MG!MTB"
        threat_id = "2147818640"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 0f af 0d ?? ?? ?? ?? 44 03 c0 48 8b 05 ?? ?? ?? ?? 49 83 c3 04 44 89 05 ?? ?? ?? ?? 41 8b d1 c1 ea 10 88 14 01 41 8b d1 8b 05 ?? ?? ?? ?? 03 c6 c1 ea 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_MG_2147818640_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.MG!MTB"
        threat_id = "2147818640"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "PluginInit" ascii //weight: 10
        $x_1_2 = "AKosuGUp" ascii //weight: 1
        $x_1_3 = "AZlRdUYbVLn" ascii //weight: 1
        $x_1_4 = "Tt.dll" ascii //weight: 1
        $x_1_5 = "BAyXfcDmcK" ascii //weight: 1
        $x_1_6 = "CfOawgoouJf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_MG_2147818640_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.MG!MTB"
        threat_id = "2147818640"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 8b 4c 24 08 8a 09 66 3b c0 74 00 88 08 48 8b 04 24 3a db 74 1a 4c 89 44 24 18 48 89 54 24 10 3a f6 74 17 48 8b 44 24 08 48 ff c0 3a c9 74 25 48 ff c0 48 89 04 24 3a e4 74 e9}  //weight: 5, accuracy: High
        $x_5_2 = "biayusdjasdugayshgdjaksa" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_PMA_2147827208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.PMA!MTB"
        threat_id = "2147827208"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ygawbhjkdhabshdjas" ascii //weight: 1
        $x_1_2 = "OnIaihEAV5" ascii //weight: 1
        $x_1_3 = "ZQQaof" ascii //weight: 1
        $x_1_4 = "bSkKYpcp" ascii //weight: 1
        $x_1_5 = "fZG5qReSX4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_CAC_2147828139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.CAC!MTB"
        threat_id = "2147828139"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4b 8d 14 08 49 ff c0 8a 42 40 32 02 88 44 11 40 49 83 f8 20 72 ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_PAA_2147829821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.PAA!MTB"
        threat_id = "2147829821"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 33 00 00 00 f7 f9 48 63 ca 48 8b 84 24 ?? ?? ?? ?? 0f b6 04 08 8b d7 33 d0 48 63 8c 24 ?? ?? ?? ?? 48 8b 84 24 ?? ?? ?? ?? 88 14 08 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_PAA_2147829821_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.PAA!MTB"
        threat_id = "2147829821"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "AqHtln" ascii //weight: 1
        $x_1_3 = "EnzSboHTFGaDooGd" ascii //weight: 1
        $x_1_4 = "HsIXgYo" ascii //weight: 1
        $x_1_5 = "SxRWqop" ascii //weight: 1
        $x_1_6 = "YKNEvMygTdzM" ascii //weight: 1
        $x_1_7 = "cSXCJThfoKE" ascii //weight: 1
        $x_1_8 = "AfbeBUWQyvfA" ascii //weight: 1
        $x_1_9 = "CgKUyXcOWcziHwN" ascii //weight: 1
        $x_1_10 = "IIytjHVPVJTHMdof" ascii //weight: 1
        $x_1_11 = "MeNLsBvLIU" ascii //weight: 1
        $x_1_12 = "RGvNbbrtRCA" ascii //weight: 1
        $x_1_13 = "YXlmWFhLNNIUlj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IcedId_BP_2147832487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.BP!MTB"
        threat_id = "2147832487"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 0c 24 48 8b 54 24 30 eb 06 33 c8 8b c1 eb ef}  //weight: 1, accuracy: High
        $x_1_2 = {88 04 0a eb 1d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_JM_2147832488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.JM!MTB"
        threat_id = "2147832488"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 04 0a e9 31 ff ff ff eb 48 8b c2 48 98 3a e4 74 c8 80 44 24 23 01 c7 04 24 00 00 00 00 eb b4 e9 14 ff ff ff 8b 4c 24 04 33 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_HB_2147832635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.HB!MTB"
        threat_id = "2147832635"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 04 0a eb af eb 9d 8b c2 48 98 66 3b c9 74 b3 99 f7 7c 24 58 3a db 74 ee 8b 4c 24 04 33 c8 3a ed 74 98}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_JJ_2147834336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.JJ!MTB"
        threat_id = "2147834336"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 24 f7 b4 24 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 8c 24 ?? ?? ?? ?? 0f b6 04 01 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4c 24 04 33 c8 eb}  //weight: 1, accuracy: High
        $x_1_4 = {8b c1 48 63 0c 24 eb}  //weight: 1, accuracy: High
        $x_1_5 = {48 8b 94 24 ?? ?? ?? ?? 88 04 0a e9}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 04 24 ff c0 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_BL_2147841063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.BL!MTB"
        threat_id = "2147841063"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {42 31 04 01 49 83 c0 04 8b 83 a0 00 00 00 33 43 0c 83 f0 0e 89 43 0c 8b 83 a0 00 00 00 83 e8 0e 31 43 10 b8 14 00 00 00 2b 83 38 01 00 00 01 43 48 8b 4b 10 44 89 8b b8 00 00 00 8d 81 [0-4] 8b 8b a0 00 00 00 31 43 40 2b 4b 40 8b 43 10}  //weight: 4, accuracy: Low
        $x_1_2 = "Hcrza4h2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_PAC_2147841979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.PAC!MTB"
        threat_id = "2147841979"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 ff c0 f7 ed 03 d5 c1 fa 05 8b c2 c1 e8 1f 03 d0 8b c5 ff c5 6b d2 23 2b c2 48 63 c8 48 8b 84 24 [0-4] 42 0f b6 0c 09 41 32 4c 00 ?? 43 88 4c 18 ?? 3b ac 24 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_AID_2147845006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.AID!MTB"
        threat_id = "2147845006"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b c2 6b c8 ?? 41 8b c3 f7 e9 03 d1 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 41 8b c3 83 c1 ?? f7 e9 03 d1 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 41 88 09 49 ff c1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_PAE_2147845556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.PAE!MTB"
        threat_id = "2147845556"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "t_gss_c_attr_local_login_user" ascii //weight: 1
        $x_1_2 = "gssspi_acquire_cred_with_password" ascii //weight: 1
        $x_1_3 = "t_gss_c_nt_hostbased_service_x_oid_desc" ascii //weight: 1
        $x_1_4 = "t_gss_krb5_export_lucid_context_x_oid_desc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_PAG_2147891858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.PAG!MTB"
        threat_id = "2147891858"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "scab" ascii //weight: 1
        $x_1_2 = "Qt5Multimedia.pdb" ascii //weight: 1
        $x_1_3 = "ng@@QEHAA?AV1@XZ" ascii //weight: 1
        $x_1_4 = "qwritableChanged@QMetaDataWriterControl@@QEAAX_N@Z" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_PAH_2147897121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.PAH!MTB"
        threat_id = "2147897121"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ler@wxEvtHandler@@UEAAXPEAV1@@Z" ascii //weight: 1
        $x_1_2 = "?Stop@wxTimer@@UEAAXXZ" ascii //weight: 1
        $x_1_3 = "0wxURI@@QEAA@AEBVwxString@@@Z" ascii //weight: 1
        $x_1_4 = "wxmsw313ud_html_vc_x64_custom.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_PAI_2147897397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.PAI!MTB"
        threat_id = "2147897397"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 81 e2 ff 00 00 00 03 c2 25 ff 00 00 00 2b c2 48 98 48 8b 4c 24 ?? 0f b6 04 01 48 63 4c 24 ?? 48 8b 54 24 ?? 0f b6 0c 0a 33 c1 48 63 4c 24 ?? 48 8b 54 24 ?? 88 04 0a e9 [0-4] 48 83 [0-2] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IcedId_HZ_2147925497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IcedId.HZ!MTB"
        threat_id = "2147925497"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 63 c8 49 8b c0 48 f7 e1 48 c1 ea ?? 48 6b c2 ?? 48 2b c8 49 0f af cb 0f b6 44 0c ?? 42 32 44 0b ?? 41 88 41 ?? 48 ff cf}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

