rule Trojan_MSIL_NanoCore_CM_2147746122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.CM!eml"
        threat_id = "2147746122"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "LuciferWeb.exe" wide //weight: 1
        $x_1_2 = {46 65 61 74 75 72 65 ?? 64 65 61 64 ?? 63 6f 64 65 54}  //weight: 1, accuracy: Low
        $x_1_3 = "lsedlacek 2015 - 2019" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_MR_2147748441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.MR!MTB"
        threat_id = "2147748441"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 16 0b 16 0c 2b 1b 02 08 02 08 91 06 07 25 17 58 0b 91 61 d2 9c 07 06 8e 69 33 02 16 0b 08 17 58 0c 08 02 8e 69 32 df 02 2a 0b 00 28 ?? ?? ?? ?? 03 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {0c 06 07 6f ?? ?? ?? ?? 08 6f ?? ?? ?? ?? 0d 62 00 7e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0a 28 ?? ?? ?? ?? 1f 22 8d ?? ?? ?? ?? 25 d0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 28 ?? ?? ?? ?? 1f 0a 8d ?? ?? ?? ?? 25 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_MIB_2147748536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.MIB!MTB"
        threat_id = "2147748536"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 9a 13 04 73 ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 04 2f 00 0b 28 ?? ?? ?? ?? 06 07 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0c 08 72 ?? ?? ?? ?? ?? ?? ?? ?? ?? 0d 09 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_VN_2147754002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.VN!MTB"
        threat_id = "2147754002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 16 1f ?? 9c 06 17 1f ?? 9c 06 28 ?? ?? ?? 0a 0b 38 ?? ?? ?? 00 07 2a 06 00 00 28 ?? ?? ?? 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_VN_2147754002_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.VN!MTB"
        threat_id = "2147754002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "VM.Main" wide //weight: 2
        $x_2_2 = "PE.Main" wide //weight: 2
        $x_2_3 = "Load" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_VN_2147754002_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.VN!MTB"
        threat_id = "2147754002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 0b 07 16 20 ?? ?? ?? ?? 28 ?? ?? ?? 06 a2 07 17 20 ?? ?? ?? ?? 28 ?? ?? ?? 06 a2 07 18 20 ?? ?? ?? ?? 28 ?? ?? ?? 06 a2 07 a2 06 18 14 a2 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_VN_2147754002_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.VN!MTB"
        threat_id = "2147754002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0b 07 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 0c 08 14 18 8d ?? ?? ?? 01 25 16 7e ?? ?? ?? 04 a2 25 17 72 ?? ?? ?? 70 a2 6f ?? ?? ?? 0a 0d 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_VN_2147754002_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.VN!MTB"
        threat_id = "2147754002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 14 18 8d ?? ?? ?? 01 25 16 7e ?? ?? ?? 04 a2 25 17 72 ?? ?? ?? 70 a2 6f ?? ?? ?? 0a 26 2a 0c 00 00 03 72 ?? ?? ?? 70 6f ?? ?? ?? 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_VN_2147754002_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.VN!MTB"
        threat_id = "2147754002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 72 b9 00 00 70 28 ?? ?? ?? 06 0c 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 06 14 72 ?? ?? ?? 70 18 8d ?? ?? ?? 01 0d 09 16 14 a2 00 09 17 14 a2 00 09 14 14 14 17 28 ?? ?? ?? 0a 26 00 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_VN_2147754002_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.VN!MTB"
        threat_id = "2147754002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 09 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 07 08 93 61 d1 13 ?? 06 11 ?? 6f ?? ?? ?? 0a 26 08 04 6f ?? ?? ?? 0a 17 59 33 ?? 16 0c 2b ?? 08 1f ?? 58 1f ?? 59 0c 09 18 58 0d 09 03 6f ?? ?? ?? 0a 17 59 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_VN_2147754002_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.VN!MTB"
        threat_id = "2147754002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 16 0c 16 0d 2b ?? 03 09 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 07 08 93 61 d1 13 ?? 06 11 ?? 6f ?? ?? ?? 0a 26 08 04 6f ?? ?? ?? 0a 17 59 33 ?? 16 0c 2b ?? 08 17 58 0c 09 18 58 0d 09 03 6f ?? ?? ?? 0a 17 59 31 ?? 06 6f ?? ?? ?? 0a 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_VN_2147754002_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.VN!MTB"
        threat_id = "2147754002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OJIAUHDOUHDUOADG" ascii //weight: 1
        $x_1_2 = "password" ascii //weight: 1
        $x_1_3 = "BlockCopy" ascii //weight: 1
        $x_1_4 = "$22fe648f-2e6b-4b8a-bb5b-020f4e3828a4" ascii //weight: 1
        $x_1_5 = "SnakeTroops" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_VN_2147754002_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.VN!MTB"
        threat_id = "2147754002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 02 06 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b 07 6f ?? ?? ?? 0a 18 9a 14 19 8d ?? ?? ?? 01 25 16 7e ?? ?? ?? 04 a2 25 17 7e ?? ?? ?? 04 a2 25 18 72 ?? ?? ?? 70 a2 0c 08 6f ?? ?? ?? 0a 26 16 28 ?? ?? ?? 0a 00 16 0d 2b ?? 09 2a 11 00 00 02 28 ?? ?? ?? 06 28 ?? ?? ?? 06 0a 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_VN_2147754002_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.VN!MTB"
        threat_id = "2147754002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OJIAUHDOUHDUOADG" ascii //weight: 1
        $x_1_2 = "password" ascii //weight: 1
        $x_1_3 = "uhfsihfnf" ascii //weight: 1
        $x_1_4 = "BlockCopy" ascii //weight: 1
        $x_1_5 = "$efd82296-247e-46dc-bcba-b87a11f4b920" ascii //weight: 1
        $x_1_6 = "SnakeIdApp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_VN_2147754002_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.VN!MTB"
        threat_id = "2147754002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_2 = "Debugger" ascii //weight: 1
        $x_1_3 = "asdadsadsadsada" ascii //weight: 1
        $x_1_4 = "ReadByte" ascii //weight: 1
        $x_1_5 = "BlockCopy" ascii //weight: 1
        $x_1_6 = "WriteLine" ascii //weight: 1
        $x_1_7 = "$546cfb94-1595-4371-b2e7-367a8d6f6100" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_VN_2147754002_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.VN!MTB"
        threat_id = "2147754002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 17 58 20 ?? ?? ?? 00 5f 0c 09 11 ?? 08 95 58 20 ?? ?? ?? 00 5f 0d 11 ?? 08 95 13 ?? 11 ?? 08 11 ?? 09 95 9e 11 ?? 09 11 ?? 9e 11 ?? 11 ?? d4 06 11 ?? d4 91 11 ?? 11 ?? 08 95 11 ?? 09 95 58 20 ?? ?? ?? 00 5f 95 61 28 ?? ?? ?? 0a 9c 00 11 ?? 17 6a 58 13 ?? 11 ?? 11 ?? 8e 69 17 59 6a fe ?? 16}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_VN_2147754002_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.VN!MTB"
        threat_id = "2147754002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_2 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_3 = "sdadsadadasd" ascii //weight: 1
        $x_1_4 = "ReadByte" ascii //weight: 1
        $x_1_5 = "BlockCopy" ascii //weight: 1
        $x_1_6 = "Write" ascii //weight: 1
        $x_1_7 = "$8655ac67-9ebc-4896-b5e9-a5670bbe9ca8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_MA_2147814037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.MA!MTB"
        threat_id = "2147814037"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HyT3NGnBTYHXcJwFYv" wide //weight: 1
        $x_1_2 = "vhOxRD2j5Rpxq3LSAC" wide //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "MemoryStream" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "Debugger" ascii //weight: 1
        $x_1_7 = "IsLogging" ascii //weight: 1
        $x_1_8 = "Reverse" ascii //weight: 1
        $x_1_9 = "set_Key" ascii //weight: 1
        $x_1_10 = "TransformFinalBlock" ascii //weight: 1
        $x_1_11 = "CreateDecryptor" ascii //weight: 1
        $x_1_12 = "NanoCore.ServerPluginHost" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_RPG_2147825428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.RPG!MTB"
        threat_id = "2147825428"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 72 0e 1d 00 70 72 12 1d 00 70 6f 0d 00 00 0a 10 00 02 6f 0e 00 00 0a 18 5b 8d 0c 00 00 01 0a 16 0b 38 18 00 00 00 06 07 02 07 18 5a 18 6f 0f 00 00 0a 1f 10 28 10 00 00 0a 9c 07 17 58 0b 07 06 8e 69 32 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_NEA_2147828319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.NEA!MTB"
        threat_id = "2147828319"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$dd90f1c7-f1f8-4eb4-a9f6-b9f890d2e08f" ascii //weight: 1
        $x_1_2 = "swxben.Windows" ascii //weight: 1
        $x_1_3 = "EM_SETCUEBANNER" ascii //weight: 1
        $x_1_4 = "CC BY-SA 3.0" ascii //weight: 1
        $x_1_5 = "QADGWGG" ascii //weight: 1
        $x_1_6 = "ECM_FIRST" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_NEB_2147829995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.NEB!MTB"
        threat_id = "2147829995"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qU0lNKKCOjGOScCojY" ascii //weight: 1
        $x_1_2 = "oxOsQ0TymUGAkm3LQ9" ascii //weight: 1
        $x_1_3 = "dcNEsXtCfY5qH95fek" ascii //weight: 1
        $x_1_4 = "DE8X2tmJ7K2bF3wgbGU" ascii //weight: 1
        $x_1_5 = "sKHuBvF4a" ascii //weight: 1
        $x_1_6 = "G5eodYpHOMSRqWbfyv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_CB_2147838903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.CB!MTB"
        threat_id = "2147838903"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EVB_8474AF4CAB1BA486_00000E30" ascii //weight: 1
        $x_1_2 = "animation.RenderNodeAnimator.module9.exe" ascii //weight: 1
        $x_1_3 = "set_SecurityProtocol" ascii //weight: 1
        $x_1_4 = "WebRequest" ascii //weight: 1
        $x_1_5 = "qvirtualboxglobalsunit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_FAT_2147845852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.FAT!MTB"
        threat_id = "2147845852"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 04 17 58 0c 02 11 04 09 28 ?? 00 00 06 02 11 04 09 28 ?? 00 00 06 91 06 11 04 06 8e 69 28 ?? 00 00 06 91 61 02 08 09 28 ?? 00 00 06 91 28 ?? 00 00 06 07 58 07 5d d2 9c 11 04 15 58 13 04 11 04 16 2f bc}  //weight: 3, accuracy: Low
        $x_2_2 = "NoYou" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_RPX_2147848106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.RPX!MTB"
        threat_id = "2147848106"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 00 30 00 38 00 2e 00 36 00 37 00 2e 00 31 00 30 00 37 00 2e 00 31 00 34 00 36 00 2f 00 [0-32] 2e 00 62 00 6d 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Sys_tem.Del_egate" wide //weight: 1
        $x_1_3 = "Dyn_am_icInv_oke" wide //weight: 1
        $x_1_4 = "Syste_m.Refl_ection.As_sembly" wide //weight: 1
        $x_1_5 = "Replace" wide //weight: 1
        $x_1_6 = "Ge_tExp_ortedTy_pes" wide //weight: 1
        $x_1_7 = "Lo_ad" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_DA_2147897039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.DA!MTB"
        threat_id = "2147897039"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "NanoCore Client" ascii //weight: 20
        $x_1_2 = "KeyboardLogging" ascii //weight: 1
        $x_1_3 = ".ClientPluginHost" ascii //weight: 1
        $x_1_4 = "ClientInvokeDelegate" ascii //weight: 1
        $x_1_5 = "PipeCreated" ascii //weight: 1
        $x_1_6 = "get_ClientSettings" ascii //weight: 1
        $x_1_7 = "get_Connected" ascii //weight: 1
        $x_1_8 = "My.Computer" ascii //weight: 1
        $x_1_9 = "System.Runtime.InteropServices" ascii //weight: 1
        $x_1_10 = "MONEY MEN-$$$$" ascii //weight: 1
        $x_1_11 = "BypassUserAccountControl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_NanoCore_DA_2147897039_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.DA!MTB"
        threat_id = "2147897039"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RHOuPmfGOVi4LG7OdH60JWyFVnmuL2" ascii //weight: 1
        $x_1_2 = "mJXL0XmS4O3fKe2OpMznMcn6CBmfFcH61cUXOY16kOmftZWWwAmPFc2a4cWXOY1WTK2" ascii //weight: 1
        $x_1_3 = "OLEOzLmfTWGzmGGfKc1mpOGvFcDGcLmaQcG" ascii //weight: 1
        $x_1_4 = "pFVLEZGOpI23FLG24Pl3oYnivL2zfU2WwK2vFLFm4PkbKY2vmezWeLjLmC3HYcme" ascii //weight: 1
        $x_1_5 = "Je3OYMnLHeHi4ODnJdmi4JnTGLHmwJWnOY2+uPg==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_GNM_2147923793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.GNM!MTB"
        threat_id = "2147923793"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0d 07 08 08 6f ?? ?? ?? 0a 13 05 73 32 00 00 0a 13 06 11 06 11 05 17 73 33 00 00 0a 13 07 11 07 09 16 09 8e 69 6f ?? ?? ?? 0a 11 07 6f ?? ?? ?? 0a 11 07 6f ?? ?? ?? 0a 11 07 6f ?? ?? ?? 0a de 0c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_MBWD_2147927704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.MBWD!MTB"
        threat_id = "2147927704"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {59 0d 06 09 03 08 18 6f ?? 00 00 0a 1f ?? 28 ?? 00 00 0a 07 09 07 8e 69 5d 91 61 d2 9c}  //weight: 2, accuracy: Low
        $x_1_2 = "racoon.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_PLAH_2147928654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.PLAH!MTB"
        threat_id = "2147928654"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 11 05 03 11 05 91 11 04 61 06 08 91 61 b4 9c 08 02 6f ?? 00 00 0a 17 da 33 04 16 0c 2b 04 08 17 d6 0c 11 05 17 d6 13 05 11 05 11 06 31 d1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_BL_2147933059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.BL!MTB"
        threat_id = "2147933059"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 10 00 02 28 ?? 00 00 0a 0d 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 00 09 73 ?? 00 00 0a 13 05 00 11 05 11 04 16 73 ?? 00 00 0a 13 06}  //weight: 3, accuracy: Low
        $x_1_2 = "41.216.188.198/Panel/page.php" wide //weight: 1
        $x_1_3 = "vSBUyYcgKOgzYy0nDLQex7k6kSCdTt6T" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCore_ZSL_2147956684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCore.ZSL!MTB"
        threat_id = "2147956684"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 11 0a 11 0b 6f ?? 00 00 0a 13 0d 12 0d 28 ?? 00 00 0a 06 07 6f ?? 00 00 0a 59 13 0f 1f 10 13 10 1e 13 11 16 13 12 25 11 10 1f 1f 5f 63 20 ff 00 00 00 5f d2 13 13 25}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

