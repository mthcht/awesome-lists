rule Trojan_MSIL_FormBook_I_2147750161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.I!MTB"
        threat_id = "2147750161"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 15 00 00 0a 06 16 20 e8 03 00 00 6f 16 00 00 0a 8c 1a 00 00 01 08 17 9a 28 17 00 00 0a 13 04 11 04 09 28 18 00 00 0a 00 11 04}  //weight: 1, accuracy: High
        $x_1_2 = {11 04 8f 30 00 00 01 25 71 30 00 00 01 09 09 06 e0 95 09 07 e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_X_2147750856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.X!MTB"
        threat_id = "2147750856"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 07 02 8e 69 6a 5d b7 02 07 02 8e 69 6a 5d b7 91 03 07 03 8e 69 6a 5d b7 91 61 02 07 17 6a d6 02 8e 69 6a 5d b7 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 07 17 6a d6 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_Z_2147750857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.Z!MTB"
        threat_id = "2147750857"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 02 07 02 8e 69 6a 5d b7 02 07 02 8e 69 6a 5d b7 91 03 07 03 8e 69 6a 5d b7 91 61 02 07 17 6a d6 02 8e 69 6a 5d b7 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 00 07 17 6a d6 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AJ_2147751483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AJ!MTB"
        threat_id = "2147751483"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 08 06 8e 69 6a 5d 69 06 08 06 8e 69 6a 5d 69 91 02 08 02 8e 69 6a 5d 69 91 61 06 08 17 6a 58 06 8e 69 6a 5d 69 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AK_2147751616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AK!MTB"
        threat_id = "2147751616"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 13 0a 2b 56 00 07 11 08 11 0a 6f 97 00 00 0a 13 0b 11 0b 16 16 16 16 28 98 00 00 0a 28 99 00 00 0a 13 0c 11 0c 2c 2c 00 08 12 0b 28 9a 00 00 0a 6f 9b 00 00 0a 00 08 12 0b 28 9c 00 00 0a 6f 9b 00 00 0a 00 08 12 0b 28 9d 00 00 0a 6f 9b 00 00 0a 00 00 00 11 0a 17 d6 13 0a 11 0a 11 09 fe 02 16 fe 01 13 0d 11 0d 2d 9b}  //weight: 2, accuracy: High
        $x_1_2 = "FlyingThroughUniverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_BQ_2147753020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.BQ!MTB"
        threat_id = "2147753020"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 06 08 6f ?? 00 00 0a 0d 0e 04 0e 04 4a 17 58 54 07}  //weight: 2, accuracy: Low
        $x_2_2 = {58 58 0b 02 09 04 05 28}  //weight: 2, accuracy: High
        $x_1_3 = {25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_F_2147753903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.F!MTB"
        threat_id = "2147753903"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 8e b7 0c 16 03 8e b7 17 da 13 07 0d 2b 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 09 03}  //weight: 1, accuracy: Low
        $x_1_2 = {11 06 8e b7 13 04 16 03 8e b7 17 da 13 0e 13 0a 2b 4c 20 75 d4 57 4a 13 09 22 00 00 98 41 13 0b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 11 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {06 8e b7 0b 16 02 8e b7 17 da 13 07 0d 2b 70 02 09 02 09 91 06}  //weight: 1, accuracy: High
        $x_1_4 = {07 8e b7 0a 16 02 8e b7 17 da 13 07 13 05 2b 15 02 11 05 02 11 05 91}  //weight: 1, accuracy: High
        $x_1_5 = {11 06 8e b7 0c 16 0e 04 8e b7 17 da 13 10 13 0b 2b 19 0e 04 11 0b 0e 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_FormBook_A_2147754043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.A!MTB"
        threat_id = "2147754043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 73 20 00 00 0a 0a 73 1e 00 00 06 0b 1b 8d 92 00 00 01 0c 06 08 16 1b 6f 21 00 00 0a 26 07 08 6f 24 00 00 06 16 6a 0d 16 13 06 2b 1d 06 6f 22 00 00 0a}  //weight: 2, accuracy: High
        $x_1_2 = "c41f42b3-5872-4118-a64e-90e723637ff6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_B_2147754448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.B!MTB"
        threat_id = "2147754448"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 16 1f 4c 9d 25 17 1f 6f 9d 25 18 1f 61 9d 25 19 1f 64 9d 2a}  //weight: 1, accuracy: High
        $x_1_2 = "be-run-in QOS zode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_B_2147754448_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.B!MTB"
        threat_id = "2147754448"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {11 06 75 0d 00 00 1b 11 07 8f 01 00 00 01 25 71 01 00 00 01 11 07 02 58 05 59 20 ff 00 00 00 5f d2 61 d2 81 01 00 00 01 11 12 20 b6 01 00 00 91 20 c2 00 00 00 59 13 10}  //weight: 3, accuracy: High
        $x_1_2 = "1f92ecae-a0e1-496a-a610-00ded71b7d75" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_SK_2147755589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.SK!MTB"
        threat_id = "2147755589"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeypadFormSampler" ascii //weight: 1
        $x_1_2 = "DependencyPropertyWeaver.Properties" ascii //weight: 1
        $x_1_3 = "$E4B7A3F9-6C2D-4A8E-9F5B-1D8A4C7E2B6F" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_SK_2147755589_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.SK!MTB"
        threat_id = "2147755589"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 95 00 00 00 5a 11 0e 1a 63 61 61 13 0e 1f 55 13 38 38 13 f3 ff ff 16 13 2c 11 39 20 c8 00 00 00 93 20 de 77 00 00 59 13 38 38 fb f2 ff ff 02 11 2b 11 2c 20 f4 03 00 00 20 eb 03 00 00 28 2d 00 00 2b 13 2d 04 03 6f a4 00 00 0a 59}  //weight: 1, accuracy: High
        $x_1_2 = "SolarSystem.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_SK_2147755589_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.SK!MTB"
        threat_id = "2147755589"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 06 75 07 00 00 02 7b 17 00 00 04 20 a1 03 00 00 20 cc 03 00 00 28 14 00 00 2b 28 53 00 00 0a 06 75 07 00 00 02 fe 06 4c 00 00 06 73 54 00 00 0a 28 15 00 00 2b 7e 1b 00 00 04 25 2d 17 26 7e 1a 00 00 04 fe 06 53 00 00 06 73 56 00 00 0a 25 80 1b 00 00 04 28 16 00 00 2b 04 28 17 00 00 2b 0b 03 07 74 08 00 00 1b 6f 58 00 00 0a 2a}  //weight: 1, accuracy: High
        $x_1_2 = "HostPinger.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_FI_2147767657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.FI!MTB"
        threat_id = "2147767657"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "uy32e123" ascii //weight: 20
        $x_20_2 = "sdfsdfsadea" ascii //weight: 20
        $x_20_3 = "gsdfasdfas" ascii //weight: 20
        $x_20_4 = "dik3iaowdasd" ascii //weight: 20
        $x_20_5 = "mkaskdadas" ascii //weight: 20
        $x_1_6 = "Non Obfuscated" ascii //weight: 1
        $x_1_7 = "VirtualProtect" ascii //weight: 1
        $x_1_8 = "ToBase64String" ascii //weight: 1
        $x_1_9 = "get_CurrentDomain" ascii //weight: 1
        $x_1_10 = "DebuggingModes" ascii //weight: 1
        $x_1_11 = "ResolveSignature" ascii //weight: 1
        $x_1_12 = "LoadModule" ascii //weight: 1
        $x_1_13 = "Convert" ascii //weight: 1
        $x_1_14 = "GetTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 8 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_FormBook_FD_2147771275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.FD!MTB"
        threat_id = "2147771275"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$fad79bec-ae07-4989-bbb1-bf5707e5d799" ascii //weight: 20
        $x_20_2 = "$BF966935-F362-4BFF-AF96-B83B5D5B88CA" ascii //weight: 20
        $x_20_3 = "$7cf7e07a-9188-40b4-8a00-a72c6daa30e5" ascii //weight: 20
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "OpenFTP.Properties.Resources" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_7 = "TTSI.BARCODES.Resources.resources" ascii //weight: 1
        $x_1_8 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_9 = "CloudaryStorage.Form1.resources" ascii //weight: 1
        $x_1_10 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_11 = "CreateInstance" ascii //weight: 1
        $x_1_12 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_13 = "Activator" ascii //weight: 1
        $x_1_14 = "DebuggableAttribute" ascii //weight: 1
        $x_1_15 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_FormBook_FD_2147771275_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.FD!MTB"
        threat_id = "2147771275"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$fb35f5e9-c9b0-44bb-b0b8-2ac7073c816e" ascii //weight: 20
        $x_20_2 = "$98522dab-f3e6-4b7c-bb7f-5bb07ec76575" ascii //weight: 20
        $x_20_3 = "$017f8eb7-0769-4e50-bad8-c7d1041c74c7" ascii //weight: 20
        $x_20_4 = "$d9e319be-47e0-48c2-9ccb-b6c3b7205466" ascii //weight: 20
        $x_1_5 = "Audio_Realtek_Driver.Resources" ascii //weight: 1
        $x_1_6 = "Win.My.Resources" ascii //weight: 1
        $x_1_7 = "Gunz_Launcher.Resources.resources" ascii //weight: 1
        $x_1_8 = "Sudoku_Online.Properties.Resources" ascii //weight: 1
        $x_1_9 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_10 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_11 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_12 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_13 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_14 = "DebuggableAttribute" ascii //weight: 1
        $x_1_15 = "DebuggingModes" ascii //weight: 1
        $x_1_16 = "CreateInstance" ascii //weight: 1
        $x_1_17 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_FormBook_FE_2147780075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.FE!MTB"
        threat_id = "2147780075"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$5a40a243-da62-4db5-a9d6-2f2018867a50" ascii //weight: 20
        $x_20_2 = "$3454746C-DDEE-4133-98ED-0362E57B60A0" ascii //weight: 20
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_4 = "LifetimeEntry.Properties.Resources" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_6 = "ExpTreeLib.Resources.resources" ascii //weight: 1
        $x_1_7 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_8 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_9 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
        $x_1_11 = "DebuggingModes" ascii //weight: 1
        $x_1_12 = "CreateInstance" ascii //weight: 1
        $x_1_13 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_FormBook_FE_2147780075_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.FE!MTB"
        threat_id = "2147780075"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$c1467c12-1af8-44da-80ec-63f362be50eb" ascii //weight: 20
        $x_20_2 = "$1ce8c8cf-8669-4a3d-946d-0b26b09b0374" ascii //weight: 20
        $x_20_3 = "$3590d7cb-154a-4c6a-9120-abcad6e22eea" ascii //weight: 20
        $x_20_4 = "$0eaf8fc6-403b-4b7b-8368-3a944a215231" ascii //weight: 20
        $x_20_5 = "$5bf6359b-c0d9-4003-9550-435e29218260" ascii //weight: 20
        $x_1_6 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_8 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_9 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_12 = "Activator" ascii //weight: 1
        $x_1_13 = "DebuggableAttribute" ascii //weight: 1
        $x_1_14 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_FormBook_FF_2147780335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.FF!MTB"
        threat_id = "2147780335"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$de68feeb-2211-40da-94fe-b720ed534f6f" ascii //weight: 20
        $x_20_2 = "$4c230219-93e9-426d-8797-9b75258cb46e" ascii //weight: 20
        $x_20_3 = "$a236408f-d04c-4514-8bde-bf41cc7247f1" ascii //weight: 20
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_8 = "CreateInstance" ascii //weight: 1
        $x_1_9 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_10 = "Activator" ascii //weight: 1
        $x_1_11 = "DebuggableAttribute" ascii //weight: 1
        $x_1_12 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_FormBook_FF_2147780335_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.FF!MTB"
        threat_id = "2147780335"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$f1c941af-cf72-40e3-95e7-5f9b1620fee0" ascii //weight: 20
        $x_20_2 = "$DC4D53C8-8832-4500-9599-D94D6FA55920" ascii //weight: 20
        $x_20_3 = "$230df148-83a0-40c2-846a-71e7e7e37799" ascii //weight: 20
        $x_20_4 = "$50F7D21A-0580-4812-9B6B-404CC8442C8D" ascii //weight: 20
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_6 = "ManagerMarket.My.Resources" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_8 = "MarshalOverride.Properties.Resources.resources" ascii //weight: 1
        $x_1_9 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_10 = "ManagerGame.Resources.resources" ascii //weight: 1
        $x_1_11 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_12 = "LoaderOptimization.Resources.resources" ascii //weight: 1
        $x_1_13 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_14 = "CreateInstance" ascii //weight: 1
        $x_1_15 = "DebuggableAttribute" ascii //weight: 1
        $x_1_16 = "Activator" ascii //weight: 1
        $x_1_17 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_FormBook_FG_2147780437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.FG!MTB"
        threat_id = "2147780437"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 13 04 72 ?? ?? ?? 70 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 13 05 08 09 18 17 8d 01 00 00 01 13 08 11 08 16 07 a2 11 08 28 ?? ?? ?? 0a 13 06 11 06 11 04 18 16 8d 01 00 00 01 28 ?? ?? ?? 0a 13 07 11 07 11 05 17 18 8d 01 00 00 01 13 09 11 09 16 16 8c 15 00 00 01 a2 11 09 28 ?? ?? ?? 0a 26 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "vecrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_FG_2147780437_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.FG!MTB"
        threat_id = "2147780437"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$0410bb9a-e94d-4544-91cf-ad9442e30eeb" ascii //weight: 20
        $x_20_2 = "CPP.My.Resources" ascii //weight: 20
        $x_1_3 = "CPP.UC_Main.resources" ascii //weight: 1
        $x_1_4 = "Coffee Shop.txt" ascii //weight: 1
        $x_1_5 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "Activator" ascii //weight: 1
        $x_1_8 = "Bitmap" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 6 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_FormBook_AH_2147781938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AH!MTB"
        threat_id = "2147781938"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {57 9d a2 29 09 1f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 02 ?? ?? ?? bf ?? ?? ?? 3a ?? ?? ?? b2}  //weight: 10, accuracy: Low
        $x_3_2 = "get_Password" ascii //weight: 3
        $x_3_3 = "DelegateAsyncState" ascii //weight: 3
        $x_3_4 = "EmailLabel" ascii //weight: 3
        $x_3_5 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AH_2147781938_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AH!MTB"
        threat_id = "2147781938"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 11 08 72 35 00 00 70 28 ?? ?? ?? 0a 72 53 00 00 70 20 00 01 00 00 14 14 18 8d 12 00 00 01 25 16 06 11 08 9a a2 25 17 1f 10 8c 7f 00 00 01 a2}  //weight: 2, accuracy: Low
        $x_1_2 = "AC_Control" wide //weight: 1
        $x_1_3 = "P#es.Wh#te" wide //weight: 1
        $x_1_4 = "Replace" ascii //weight: 1
        $x_1_5 = "System.Convert" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_HA_2147782493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.HA!MTB"
        threat_id = "2147782493"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NimitzDEV" ascii //weight: 1
        $x_1_2 = "ISectionEntry" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "regKeyPath" ascii //weight: 1
        $x_1_6 = "DownloadList" ascii //weight: 1
        $x_1_7 = "ToWin32" ascii //weight: 1
        $x_1_8 = "DebuggingModes" ascii //weight: 1
        $x_1_9 = "Activator" ascii //weight: 1
        $x_1_10 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_11 = "DebuggableAttribute" ascii //weight: 1
        $x_1_12 = "setProxy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_GO_2147782497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.GO!MTB"
        threat_id = "2147782497"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GZIDEKKKK" ascii //weight: 1
        $x_1_2 = "Encryptor" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "Decrypt" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "ToArray" ascii //weight: 1
        $x_1_7 = "GZipStream" ascii //weight: 1
        $x_1_8 = "StringBuilder" ascii //weight: 1
        $x_1_9 = "MD5CryptoServiceProvider" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
        $x_1_11 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_FV_2147783089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.FV!MTB"
        threat_id = "2147783089"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 09 16 73 ?? ?? ?? ?? 73 ?? ?? ?? ?? 13 04 11 04 07 6f ?? ?? ?? ?? dd ?? ?? ?? ?? 11 04 6f ?? ?? ?? ?? dc 07 6f ?? ?? ?? ?? 13 05 dd}  //weight: 10, accuracy: Low
        $x_1_2 = "ClassLibrary1" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_CUO_2147794223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.CUO!MTB"
        threat_id = "2147794223"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 04 09 11 04 20 e8 03 00 00 73 ?? ?? ?? 0a 0c 06 08 06 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 08 06 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 17 6f ?? ?? ?? 0a 02 06 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 0b 2b}  //weight: 10, accuracy: Low
        $x_10_2 = {0c 07 08 20 e8 03 00 00 73 ?? ?? ?? 0a 0d 06 09 06 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 09 06 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 17 6f ?? ?? ?? 0a 02 06 6f ?? ?? ?? 0a 17}  //weight: 10, accuracy: Low
        $x_10_3 = {13 04 09 11 04 20 e8 03 00 00 73 ?? ?? ?? 0a 0c 06 08 06 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 08 06 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 17 6f ?? ?? ?? 0a 02 06 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 0b}  //weight: 10, accuracy: Low
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = {00 43 6c 61 73 73 4c 69 62 72 61 72 79 00}  //weight: 1, accuracy: High
        $x_1_6 = "GetManifestResource" ascii //weight: 1
        $x_1_7 = "GetExecutingAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_FormBook_CVY_2147794317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.CVY!MTB"
        threat_id = "2147794317"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "BE0D4CD8V8G74444598K78" wide //weight: 10
        $x_1_2 = {00 43 32 33 34 32 35 35 36 34 37 34 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 43 32 33 35 34 32 36 35 34 33 36 37 00}  //weight: 1, accuracy: High
        $x_1_4 = "GetByte" ascii //weight: 1
        $x_1_5 = "GetType" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = {00 44 61 74 61 5f 31 00 46 69 6c 65 5f 31 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_CWG_2147794639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.CWG!MTB"
        threat_id = "2147794639"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 44 6f 49 74 00 54 72 79 46 6f 72 49 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 45 6e 63 6f 64 65 72 73 00 63 75 73 74 6f 6d 65 72 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {48 65 6c 70 65 72 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 43 6f 6e 76 65 72 74 6f 72}  //weight: 1, accuracy: Low
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "GetTypes" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
        $x_1_7 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_CWC_2147794640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.CWC!MTB"
        threat_id = "2147794640"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 00 2d 53 00 74 00 61 00 72 00 74 00 2d 00 53 00 6c 00 65 00 65 00 70 00 20 00 2d 00 53}  //weight: 1, accuracy: High
        $x_1_2 = {00 45 6e 63 6f 64 65 72 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 44 65 63 6f 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "GetTypes" ascii //weight: 1
        $x_1_6 = "Convertor" ascii //weight: 1
        $x_1_7 = "GetString" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_CXI_2147795081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.CXI!MTB"
        threat_id = "2147795081"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Test-NetConnection" wide //weight: 1
        $x_1_2 = {00 45 6e 63 6f 64 65 72 00 67 65 74 5f 52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "GetTypeFromHandle" ascii //weight: 1
        $x_1_5 = {00 43 6f 6e 76 65 72 74 6f 72 00}  //weight: 1, accuracy: High
        $x_1_6 = "GetString" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "DebuggingModes" ascii //weight: 1
        $x_1_9 = "GetMethod" ascii //weight: 1
        $x_1_10 = "GetExportedTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_LHI_2147798014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.LHI!MTB"
        threat_id = "2147798014"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 13 06 12 06 28 ?? ?? ?? 0a 17 da 13 08 16 13 09 2b 6c 00 07 11 07 11 09 6f ?? ?? ?? 0a 13 0a 11 0a 16 16 16 16 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 0b 11 0b 2c 42 00 19 8d ?? ?? ?? 01 25 16 12 0a 28 51 00 00 0a 9c 25 17 12 0a 28 52 00 00 0a 9c 25 18 11 0a 8c ?? ?? ?? 01 72 ?? ?? ?? 70 18 14 28 ?? ?? ?? 0a a5 ?? ?? ?? 01 9c 13 0c 08 11 0c 6f ?? ?? ?? 0a 00 00 00 11 09 17 d6 13 09 11 09 11 08 fe 02 16 fe 01 13 0d 11 0d 2d 85}  //weight: 1, accuracy: Low
        $x_1_2 = "FromArgb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RPZ_2147814665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RPZ!MTB"
        threat_id = "2147814665"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 28 15 00 00 0a 00 00 02 23 00 00 00 00 00 88 d3 40 73 16 00 00 0a 7d 01 00 00 04 02 7b 01 00 00 04 02 fe 06 04 00 00 06 73 17 00 00 0a 6f 18 00 00 0a 00 02 7b 01 00 00 04 17 6f 19 00 00 0a 00 02 7b 01 00 00 04 16 6f 1a 00 00 0a 00 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RPZ_2147814665_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RPZ!MTB"
        threat_id = "2147814665"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 09 5d 13 05 06 11 04 8e 69 5d 13 08 07 11 05 91 11 04 11 08 91 61 d2 13 09 11 09 07 06 17 58 09 5d 91}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RPZ_2147814665_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RPZ!MTB"
        threat_id = "2147814665"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 11 07 1e 62 08 11 08 6f 57 00 00 0a a5 14 00 00 01 60 13 09 08 11 08 11 09 1f 18 5b d2 8c 14 00 00 01 6f 58 00 00 0a 00 11 09 1f 18 5d 13 07 07 11 05 06 11 07 93 9d 00 11 08 17 59 13 08 11 08 16 fe 04 16 fe 01 13 0a 11 0a 2d b3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RPZ_2147814665_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RPZ!MTB"
        threat_id = "2147814665"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 07 09 18 6f 90 00 00 0a 1f 10 28 91 00 00 0a 13 05 08 11 05 6f 92 00 00 0a 00 09 18 58 0d 00 09 07 6f 93 00 00 0a fe 04 13 06 11 06 2d d1}  //weight: 1, accuracy: High
        $x_1_2 = "4D5A9" wide //weight: 1
        $x_1_3 = "System.Activator" wide //weight: 1
        $x_1_4 = "CreateInstance" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NPT_2147815691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NPT!MTB"
        threat_id = "2147815691"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$09e4cd08-7044-4c78-81f7-6b8efb9773f2" ascii //weight: 1
        $x_1_2 = "Datawash.Properties.Resources.resources" ascii //weight: 1
        $x_1_3 = "DebuggableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_YAU_2147816626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.YAU!MTB"
        threat_id = "2147816626"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 09 20 00 36 00 00 5d 07 09 20 00 36 00 00 5d 91 08 09 1f 16 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 06 07 09 17 58 20 00 36 00 00 5d 91 28 ?? ?? ?? 06 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? ?? ?? 06 9c 00 09 15 58 0d 09 16 fe 04 16 fe 01 13 04 11 04 2d a9}  //weight: 10, accuracy: Low
        $x_1_2 = "GetMethod" ascii //weight: 1
        $x_1_3 = "GetTypes" ascii //weight: 1
        $x_1_4 = "Invoke" ascii //weight: 1
        $x_1_5 = "TRMS.CarouselMonitorControl" wide //weight: 1
        $x_1_6 = "12DY45FF54SEY8QKYGBA5R" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_YAT_2147816627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.YAT!MTB"
        threat_id = "2147816627"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 09 20 00 36 00 00 5d 07 09 20 00 36 00 00 5d 91 08 09 1f 16 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 06 07 09 17 58 20 00 36 00 00 5d 91 28 ?? ?? ?? 06 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? ?? ?? 06 9c 00 09 15 58 0d 09 16 fe 04 16 fe 01 13 04 11 04 2d a9}  //weight: 10, accuracy: Low
        $x_1_2 = "GetMethod" ascii //weight: 1
        $x_1_3 = "GetTypes" ascii //weight: 1
        $x_1_4 = "Invoke" ascii //weight: 1
        $x_1_5 = "SwitchVsVersion" wide //weight: 1
        $x_1_6 = "12DY45FF54SEY8QKYGBA5R" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_UEA_2147816773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.UEA!MTB"
        threat_id = "2147816773"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 09 20 00 88 00 00 5d 07 09 20 00 88 00 00 5d 91 08 09 1f 16 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 06 07 09 17 58 20 00 88 00 00 5d 91 28 ?? ?? ?? 06 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? ?? ?? 06 9c 00 09 15 58 0d 09 16 fe 04 16 fe 01 13 04 11 04 2d a9}  //weight: 10, accuracy: Low
        $x_1_2 = "GetMethod" ascii //weight: 1
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "Invoke" ascii //weight: 1
        $x_1_5 = "GroupProject" wide //weight: 1
        $x_1_6 = "AF94H5HH4V78J887ZB54FD" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RVEA_2147817132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RVEA!MTB"
        threat_id = "2147817132"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 07 09 28 ?? ?? ?? 06 0b 00 09 15 58 0d 09 16 fe 04 16 fe 01 13 04 11 04 2d e4}  //weight: 1, accuracy: Low
        $x_1_2 = "GetMethod" ascii //weight: 1
        $x_1_3 = "GetTypes" ascii //weight: 1
        $x_1_4 = "Invoke" ascii //weight: 1
        $x_1_5 = "WallJumper" wide //weight: 1
        $x_1_6 = "4A7FCG8D7TJZD4Y5AS0B7G" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_PML_2147817415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.PML!MTB"
        threat_id = "2147817415"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 07 8e 69 13 05 2b 0d 00 08 07 11 05 91 6f ?? ?? ?? 0a 00 00 11 05 25 17 59 13 05 16 fe 02 13 06 11 06 2d e3}  //weight: 1, accuracy: Low
        $x_1_2 = "Progressive" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AB_2147817567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AB!MTB"
        threat_id = "2147817567"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 83 00 00 01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 07}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AB_2147817567_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AB!MTB"
        threat_id = "2147817567"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 09 00 00 fe 0c 01 00 6f ?? ?? ?? 0a 20 a0 5c bb 56 fe 0c 04 00 59 61 fe 0e 02 00 fe 0c 00 00 fe 0c 02 00 20 ?? ?? ?? 56 fe 0c 04 00 61 61 fe 09 01 00 fe 0c 01 00 fe 09 01 00 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d1 fe 0e 03 00 fe 0d 03 00 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a fe 0e 00 00 fe 0c 01 00 20 ?? ?? ?? 56 fe 0c 04 00 61 58 fe 0e 01 00 fe 0c 01 00 fe 09 00 00 6f ?? ?? ?? 0a 3f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AC_2147817760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AC!MTB"
        threat_id = "2147817760"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b6 00 b6 00 60 00 6c 25 70 00 46 00 55 00 75 00 67 00 88 25 88 25 88 25 88 25 88 25 88 25 88 25 88 25 88 25 88 25 57 00 49 00 50 00 6f 00 43 00 59 00 76 00 49 00 67 00 38 00 88 25 88 25 38 00 69 00}  //weight: 1, accuracy: High
        $x_1_2 = "Replace" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_DPL_2147817946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.DPL!MTB"
        threat_id = "2147817946"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 06 08 91 6f ?? ?? ?? 0a 00 00 08 25 17 59 0c 16 fe 02 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ERT_2147818124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ERT!MTB"
        threat_id = "2147818124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$f6d96b59-6c93-41c1-bb88-e17c2eeaf3b8" ascii //weight: 1
        $x_1_2 = "String1" wide //weight: 1
        $x_1_3 = {00 49 52 46 57 30 31 00 42 31 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 41 63 63 6f 75 6e 74 44 6f 6d 61 69 6e 53 69 64 00}  //weight: 1, accuracy: High
        $x_1_6 = "GetMethods" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ERV_2147818203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ERV!MTB"
        threat_id = "2147818203"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 01 00 00 0a 03 04 20 ?? ?? ?? ?? 5d 03 02 20 ?? ?? ?? ?? 04 28 ?? ?? ?? 06 03 04 17 58 20 ?? ?? ?? ?? 5d 91 59 06 58 06 5d d2 9c 03 0b 2b 00}  //weight: 1, accuracy: Low
        $x_1_2 = {02 05 04 5d 91 03 05 1f 16 5d 6f ?? ?? ?? 0a 61 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ERW_2147818204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ERW!MTB"
        threat_id = "2147818204"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "5GZG4BTPHZABCG755OVQZT" wide //weight: 10
        $x_5_2 = "Athlete" wide //weight: 5
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_IRL_2147818345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.IRL!MTB"
        threat_id = "2147818345"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "ToArray" ascii //weight: 5
        $x_5_2 = "DownloadData" ascii //weight: 5
        $x_5_3 = "WebClient" ascii //weight: 5
        $x_5_4 = "DynamicInvoke" ascii //weight: 5
        $x_5_5 = "GetType" ascii //weight: 5
        $x_5_6 = "GetMethod" ascii //weight: 5
        $x_1_7 = "toppnet.tk/n/Qeyed_Lecqufrk.bmp" wide //weight: 1
        $x_1_8 = "3.67.132.170/plus/loader/uploads/RT35126077_Wizdvqcj.bmp" wide //weight: 1
        $x_1_9 = "toppnet.tk/o/Mjtqm_Vzkqeeze.bmp" wide //weight: 1
        $x_1_10 = "185.222.57.252/bankreportt_Vqhsyahp.bmp" wide //weight: 1
        $x_1_11 = "lentando-slit.000webhostapp.com/mydoc/Opiqc_Erddqjkx.bmpc" wide //weight: 1
        $x_1_12 = "2.56.57.105/INVOICE_Txhlnsxi.bmp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_5_*) and 6 of ($x_1_*))) or
            ((6 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_FormBook_IRK_2147818347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.IRK!MTB"
        threat_id = "2147818347"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 16 28 02 00 0d 2b 0f 00 08 07 09 28 ?? ?? ?? 06 0b 00 09 15 58 0d 09 16 fe 04 16 fe 01 13 04 11 04 2d e4}  //weight: 1, accuracy: Low
        $x_1_2 = {00 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 00}  //weight: 1, accuracy: High
        $x_1_3 = "5GZG4BTPHZABCG755OVQZT" wide //weight: 1
        $x_1_4 = "Invoke" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ESC_2147818371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ESC!MTB"
        threat_id = "2147818371"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 01 00 00 0a 03 02 20 00 14 01 00 04 ?? ?? ?? ?? ?? 03 04 17 58 20 00 14 01 00 5d 91 59 06 58 06 5d 0b 03 04 20 00 14 01 00 5d 07 d2 9c 03 0c 08 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {02 05 04 5d 91 03 05 1f 16 5d ?? ?? ?? ?? ?? 61 0a 06 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ESD_2147818379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ESD!MTB"
        threat_id = "2147818379"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 01 00 00 0a 03 04 20 00 04 01 00 5d 03 02 20 00 04 01 00 04 ?? ?? ?? ?? ?? 03 04 17 58 20 00 04 01 00 5d 91 ?? ?? ?? ?? ?? 59 06 58 06 5d ?? ?? ?? ?? ?? 9c 03 0b 07 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {02 05 04 5d 91 03 05 1f 16 5d ?? ?? ?? ?? ?? 61 ?? ?? ?? ?? ?? 0a 06 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ESE_2147818380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ESE!MTB"
        threat_id = "2147818380"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 03 11 06 02 11 06 91 11 02 18 d6 18 da 61 11 01 11 07 19 d6 19 da 91 61 b4}  //weight: 1, accuracy: High
        $x_1_2 = {11 01 02 11 03 28 ?? ?? ?? 06 1f 10 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RPX_2147818472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RPX!MTB"
        threat_id = "2147818472"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 11 05 07 8e 69 5d 13 06 07 11 06 91 08 11 05 1f 16 5d 91 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RPX_2147818472_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RPX!MTB"
        threat_id = "2147818472"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1f 16 5d 91 13 0c 07 11 0a 91 11 07 58 13 0d 07 11 09 11 0b 11 0c 61 11 0d 11 07 5d 59 d2 9c 11 06 17 58 13 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RPX_2147818472_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RPX!MTB"
        threat_id = "2147818472"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 1f 16 5d 91 61 07 09 17 58 08 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 13 06 07 11 05 11 06 9c 11 04 07 11 05 91}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RPX_2147818472_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RPX!MTB"
        threat_id = "2147818472"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 11 05 11 08 11 04 11 08 18 5a 18 6f c0 00 00 0a 1f 10 28 c1 00 00 0a d2 9c 00 11 08 17 58 13 08 11 08 11 05 8e 69 fe 04 13 09 11 09 2d d1}  //weight: 1, accuracy: High
        $x_1_2 = "X-X-X-X-X-X-X-X-X-X-X-X-X-X-X-X-X" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RPX_2147818472_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RPX!MTB"
        threat_id = "2147818472"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "files.catbox.moe" wide //weight: 1
        $x_1_2 = "fo5y6u.vdf" wide //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CryptoStream" ascii //weight: 1
        $x_1_5 = "ToArray" ascii //weight: 1
        $x_1_6 = "ResolveThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RPY_2147818538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RPY!MTB"
        threat_id = "2147818538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 09 91 11 06 58 13 0c 07 11 08 11 0a 11 0b 61 11 0c 11 06 5d 59 d2 9c 00 11 05 17 58 13 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RPY_2147818538_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RPY!MTB"
        threat_id = "2147818538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 13 0d 11 0d 11 0c 59 20 00 01 00 00 58 20 00 01 00 00 5d 13 0e 07 11 0b 11 08 6a 5d d4 11 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RPY_2147818538_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RPY!MTB"
        threat_id = "2147818538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 06 11 04 17 58 13 07 07 11 04 91 11 05 11 06 91 61 13 08 07 11 04 11 08 07 11 07 07 8e 69 5d 91 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RPY_2147818538_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RPY!MTB"
        threat_id = "2147818538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 11 06 09 5d 13 07 11 06 08 8e 69 5d 13 08 07 11 07 91 08 11 08 91 61 d2 13 09 11 09 07 11 06 17 58 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RPY_2147818538_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RPY!MTB"
        threat_id = "2147818538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 13 0b 08 11 0b 91 11 08 58 13 0c 08 11 0a 91 13 0d 09 11 04 1f 16 5d 91 13 0e 11 0d 11 0e 61 13 0f 11 0f 11 0c 59 13 10 08 11 0a 11 10 11 08 5d d2 9c 11 04 17 58 13 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RPY_2147818538_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RPY!MTB"
        threat_id = "2147818538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1f 16 5d 91 13 05 07 11 04 91 11 05 61 13 06 11 04 17 58 07 8e 69 5d 13 07 07 11 07 91 13 08 11 06 11 08 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 09 07 11 04 11 09 d2 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 0a 11 0a 2d a1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RPY_2147818538_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RPY!MTB"
        threat_id = "2147818538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "resid=F6CFB1B6019B1562" wide //weight: 1
        $x_1_2 = "ACm4Sfbo33a6jI4" wide //weight: 1
        $x_1_3 = "history/" wide //weight: 1
        $x_1_4 = "userInfo/users.xml" wide //weight: 1
        $x_1_5 = "Eionlew" ascii //weight: 1
        $x_1_6 = "loadHistory" ascii //weight: 1
        $x_1_7 = "HttpClient" ascii //weight: 1
        $x_1_8 = "idNumber" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ESL_2147818607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ESL!MTB"
        threat_id = "2147818607"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 02 20 00 22 00 00 04 ?? ?? ?? ?? ?? 03 04 17 58 20 00 22 00 00 5d 91 ?? ?? ?? ?? ?? 59 11 03 58 11 03 5d 13 01}  //weight: 1, accuracy: Low
        $x_1_2 = {02 05 04 5d 91 13 00 ?? ?? ?? ?? ?? 11 00 03 05 1f 16 5d ?? ?? ?? ?? ?? 61 13 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ESM_2147818608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ESM!MTB"
        threat_id = "2147818608"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "38F4WP9E4HH858FASCJSB5" wide //weight: 1
        $x_1_2 = "HController" wide //weight: 1
        $x_1_3 = "GetTypes" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggingModes" ascii //weight: 1
        $x_1_6 = "GetMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ESR_2147818795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ESR!MTB"
        threat_id = "2147818795"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 05 04 5d 91 0a 06 03 05 1f 16 5d ?? ?? ?? ?? ?? 61 0b 2b 00}  //weight: 1, accuracy: Low
        $x_1_2 = "ZU057RHHH9C0GFEY75TE44" wide //weight: 1
        $x_1_3 = "DebuggableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggingModes" ascii //weight: 1
        $x_1_5 = "GetMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NU_2147818962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NU!MTB"
        threat_id = "2147818962"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 08 20 00 60 00 00 5d 06 08 20 00 60 00 00 5d 91 07 08 1f 16 5d 28 fd 01 00 06 61 06 08 17 58 20 00 60 00 00 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c}  //weight: 1, accuracy: High
        $x_1_2 = {01 57 df b6 ff 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 b0 00 00 00 24 00 00 00 97 00 00 00 67 02 00 00 f8 00 00 00 07 00 00 00 5e 01 00 00 04 00 00 00 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NU_2147818962_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NU!MTB"
        threat_id = "2147818962"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "69d7f84c-a671-4d45-9800-144738877431" ascii //weight: 4
        $x_1_2 = "txt_cPW_passwd" ascii //weight: 1
        $x_1_3 = "txt_Login_username" ascii //weight: 1
        $x_1_4 = "txt_Login_password" ascii //weight: 1
        $x_1_5 = "Invoke" ascii //weight: 1
        $x_1_6 = "buttonEncrypt_Click" ascii //weight: 1
        $x_1_7 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_DPUF_2147819043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.DPUF!MTB"
        threat_id = "2147819043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IceCreamManager" wide //weight: 1
        $x_1_2 = "HController" wide //weight: 1
        $x_1_3 = "38F4WP9E4HH858FASCJSB5" wide //weight: 1
        $x_1_4 = "Invoke" wide //weight: 1
        $x_1_5 = "a____________________" ascii //weight: 1
        $x_1_6 = "WDCWCFDRR" ascii //weight: 1
        $x_1_7 = "ToInt32" ascii //weight: 1
        $x_1_8 = "GetMethods" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_YRM_2147819211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.YRM!MTB"
        threat_id = "2147819211"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 11 05 07 11 05 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 00 11 05 17 58 13 05 11 05 08 8e 69 fe 04 13 06 11 06 2d d5}  //weight: 1, accuracy: Low
        $x_1_2 = "Alero" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_GGFA_2147819661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.GGFA!MTB"
        threat_id = "2147819661"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 0c 04 00 fe 0c 0b 00 fe 0c 04 00 fe 0c 0b 00 28 ?? ?? ?? 06 fe 0c 0b 00 28 ?? ?? ?? 06 9c fe 0c 0b 00 20 01 00 00 00 58 fe 0e 0b 00 fe 0c 0b 00 fe 0c 04 00 28 ?? ?? ?? 06 3f c1 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_HYL_2147819666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.HYL!MTB"
        threat_id = "2147819666"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 0d 00 00 0a 0a 02 8e 69 0b 2b 0a 00 06 02 07 91 2b 18 00 2b 0b 07 25 17 59 0b 16 fe 02 0c 2b 03 00 2b f2 08 2d 02 2b 09 2b e1 6f ?? ?? ?? 0a 2b e1 06 6f ?? ?? ?? 0a 0d 2b 00 09 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_TEFA_2147819756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.TEFA!MTB"
        threat_id = "2147819756"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0c 04 00 fe 0c 0e 00 fe 0c 04 00 fe 0c 0e 00 91 fe 0c 0e 00 61 d2 9c 00 fe 0c 0e 00 20 01 00 00 00 58 fe 0e 0e 00 fe 0c 0e 00 fe 0c 04 00 8e 69 fe 04 fe 0e 0f 00 fe 0c 0f 00 3a bf ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_CFFA_2147819759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.CFFA!MTB"
        threat_id = "2147819759"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0c 00 00 fe 0c 02 00 fe 0c 00 00 fe 0c 02 00 91 fe 0c 02 00 61 d2 9c 00 fe 0c 02 00 20 01 00 00 00 58 fe 0e 02 00 fe 0c 02 00 fe 0c 00 00 8e 69 fe 04 fe 0e 03 00 fe 0c 03 00 3a bf ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_PSUF_2147819760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.PSUF!MTB"
        threat_id = "2147819760"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 df 8e fb 0e 0b 07 20 e7 8e fb 0e fe 01 0c 08 2c 09 20 1f 8f fb 0e 0b 00 2b 28 07 20 f1 8e fb 0e fe 01 0d 09 2c 09 20 18 8f fb 0e 0b 00 2b 13 00 20 07 8f fb 0e 0b 17 13 04 02 28 ?? ?? ?? 06 0a 2b 00 06 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_PSUF_2147819760_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.PSUF!MTB"
        threat_id = "2147819760"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 df 8e fb 0e 0b 07 20 e7 8e fb 0e fe 01 0c 08 2c 09 20 1f 8f fb 0e 0b 00 2b 28 07 20 f1 8e fb 0e fe 01 0d 09 2c 09 20 18 8f fb 0e 0b 00 2b 13 00 20 07 8f fb 0e 0b 17 13 04 02 28 ?? ?? ?? 06 0a 2b 00 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "Bunifu_TextBox" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MDC_2147819761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MDC!MTB"
        threat_id = "2147819761"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 16 58 0c 2b 18 00 7e 17 00 00 04 07 08 20 00 01 00 00 28 ?? ?? ?? 06 0b 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d dd}  //weight: 1, accuracy: Low
        $x_1_2 = "Cod.Sponde.Uit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_TGFA_2147820109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.TGFA!MTB"
        threat_id = "2147820109"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d0 73 00 00 01 28 ?? ?? ?? 0a 0a 06 72 ?? ?? ?? 70 20 00 01 00 00 14 14 17 8d 18 00 00 01 25 16 02 a2 6f ?? ?? ?? 0a 0b 2b 00 07 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "Ducin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_SP_2147820110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.SP!MTB"
        threat_id = "2147820110"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 04 03 8e 69 28 ?? ?? ?? 06 d6 0d 09 04 5f 13 04 08 03 8e 69 28 ?? ?? ?? 06 13 05 03 11 05 91 13 06 11 06 11 04 28 ?? ?? ?? 06 28 ?? ?? ?? 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_UP_2147820112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.UP!MTB"
        threat_id = "2147820112"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 9f 25 00 70 18 17 8d 19 00 00 01 25 16 07 a2 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 26 07 28 ?? ?? ?? 0a 0a 2b 00 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "Bunifu_TextBox" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_JHFA_2147820114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.JHFA!MTB"
        threat_id = "2147820114"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 17 8d 19 00 00 01 25 16 07 a2 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 26 07 28 ?? ?? ?? 0a 0a 2b 00 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "Bunifu_TextBox" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_XZBA_2147820115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.XZBA!MTB"
        threat_id = "2147820115"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 17 8d 18 00 00 01 25 16 07 a2 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 26 07 28 ?? ?? ?? 0a 0a 2b 00 06 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_WNVF_2147820116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.WNVF!MTB"
        threat_id = "2147820116"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 17 8d 19 00 00 01 25 16 06 a2 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 26 06 28 ?? ?? ?? 0a 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EUF_2147820135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EUF!MTB"
        threat_id = "2147820135"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 03 17 58 ?? ?? ?? ?? ?? 5d 91 0a 16 0b 02 03 1f 16 ?? ?? ?? ?? ?? 0c 06 04 58 0d 08 09 59 04 5d 0b 02 03 ?? ?? ?? ?? ?? 5d 07 ?? ?? ?? ?? ?? 9c 02 13 04 11 04 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {5d 91 0a 06 ?? ?? ?? ?? ?? 03 04 5d ?? ?? ?? ?? ?? 61 0b 07 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_QHFA_2147820205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.QHFA!MTB"
        threat_id = "2147820205"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 16 08 02 00 0b 2b 13 00 06 07 20 00 01 00 00 28 ?? ?? ?? 06 0a 00 07 15 58 0b 07 16 fe 04 16 fe 01 0c 08 2d e2}  //weight: 1, accuracy: Low
        $x_1_2 = "CIS.BusinessFacade" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EUH_2147820207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EUH!MTB"
        threat_id = "2147820207"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 04 11 08 09 11 08 09 8e 69 5d 91 03 11 08 91 61 9c 11 08 17 d6 13 08 11 08 11 07 31 e2}  //weight: 1, accuracy: High
        $x_1_2 = "TRUMP" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EUH_2147820207_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EUH!MTB"
        threat_id = "2147820207"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 ea a7 00 70 17 8d 16 00 00 01 25 16 07 a2 25 0c 14 14 17 8d 87 00 00 01 25 16 17 9c 25 0d 28 ?? ?? ?? 0a 09 16 91 2d 02 2b 09 08 16 9a 28 ?? ?? ?? 0a 0b 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 26 07 28 ?? ?? ?? 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "ToCharArray" wide //weight: 1
        $x_1_3 = "FromBase64CharArray" ascii //weight: 1
        $x_1_4 = "ToString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EUI_2147820208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EUI!MTB"
        threat_id = "2147820208"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 1f 54 ?? ?? ?? ?? ?? 00 07 1f 72 ?? ?? ?? ?? ?? 00 07 1f 75 ?? ?? ?? ?? ?? 00 07 1f 6d ?? ?? ?? ?? ?? 00 07 1f 70 ?? ?? ?? ?? ?? 00 07 1f 32 ?? ?? ?? ?? ?? 00 07 1f 33 ?? ?? ?? ?? ?? 00 07 1f 34 ?? ?? ?? ?? ?? 00 07 1f 35 ?? ?? ?? ?? ?? 00 07 1f 36 ?? ?? ?? ?? ?? 00 07 1f 37 ?? ?? ?? ?? ?? 00 07 1f 61 ?? ?? ?? ?? ?? 00 07 1f 62 ?? ?? ?? ?? ?? 00 07 1f 63 ?? ?? ?? ?? ?? 00 07 1f 40 ?? ?? ?? ?? ?? 00 07 1f 2e ?? ?? ?? ?? ?? 00 07 1f 63 ?? ?? ?? ?? ?? 00 07 1f 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_OIFA_2147820235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.OIFA!MTB"
        threat_id = "2147820235"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 16 70 01 00 0b 2b 13 00 06 07 20 00 01 00 00 28 ?? ?? ?? 06 0a 00 07 15 58 0b 07 16 fe 04 16 fe 01 0c 08 2d e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EUJ_2147820275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EUJ!MTB"
        threat_id = "2147820275"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 03 66 5f 02 66 03 5f 60 ?? ?? ?? ?? ?? 0a 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "QPVMethod0QPV" wide //weight: 1
        $x_1_3 = "GetMethod" ascii //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EUK_2147820286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EUK!MTB"
        threat_id = "2147820286"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 03 17 58 ?? ?? ?? ?? ?? 5d 91 0a 16 13 05 2b 00 16 0b 16 13 06 2b 00 02 03 1f 16 ?? ?? ?? ?? ?? 0c 06 04 58 0d 08 09 59 04 5d 0b 16 13 07 2b 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5d 91 0a 06 ?? ?? ?? ?? ?? 03 04 5d ?? ?? ?? ?? ?? 61 0b 2b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EUO_2147820396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EUO!MTB"
        threat_id = "2147820396"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 03 17 58 ?? ?? ?? ?? ?? 5d 91 0a 16 0b 02 03 ?? ?? ?? ?? ?? 0c 06 04 58 0d 08 09 59 04 5d 0b 16 13 04 2b 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5d 91 0a 06 ?? ?? ?? ?? ?? 03 04 5d ?? ?? ?? ?? ?? 61 0b 2b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EUO_2147820396_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EUO!MTB"
        threat_id = "2147820396"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "57N48YJZH2VHA8G4GCF28G" wide //weight: 1
        $x_1_2 = "oa++d" wide //weight: 1
        $x_1_3 = "Rara3" wide //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EUP_2147820397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EUP!MTB"
        threat_id = "2147820397"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {db f9 ec 90 2c c0 df b1 3e 4b 3c 38 cc bb 40 2d 4a 4b 22 b1 ba 35 db f9 ec 90 2c c0 df b1 3e 4b 3c 38 cc bb 40 2d 4a 4b 22 b1 ba 35 db f9 ec 90}  //weight: 1, accuracy: High
        $x_1_2 = {3a 6d 74 62 df 91 62 6b 88 38 f4 da a6 1e 4c 52 01 4f 50 71 99 fc 44 7d 05 77 6c 4e 66 4b 9a 3e 81 20 ac 6f 4a dc 79 d0 f9 b5 84 5c 10 c1 cb 95}  //weight: 1, accuracy: High
        $x_1_3 = {2c c0 df b1 3e 4b 3c 38 cc bb 40 2d 4a 4b 22 b1 bb 37 c4 c1 e8 90 2c c0 df b1 3e 4b 3c 38 cc bb 40 2d 4a 4b 22 b1 ba 35 db f9 ec 90 2c c0 df b1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_FormBook_EUQ_2147820398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EUQ!MTB"
        threat_id = "2147820398"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 06 1f 16 d6 1f 0b da 1f 0b da 02 11 06 1f 16 d6 1f 0b da 1f 0b da 91 08 61 07 ?? ?? ?? ?? ?? 11 07 91 61 b4 9c 1f 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EUW_2147821063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EUW!MTB"
        threat_id = "2147821063"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 11 04 91 07 61 06 ?? ?? ?? ?? ?? 09 91 61 13 05 1f 0f 13 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {02 02 8e 69 17 59 91 1f 70 61 0b 11 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EUZ_2147821377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EUZ!MTB"
        threat_id = "2147821377"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 3f 4c 4d ee 32 2a cf fc c2 75 4c 67 74 7c 4e cb 71 0a da 4e 42 d9 3d 60 7b 5f 56 93 63 37 eb 31 53 10 15 9b 86 28 3a e2 c9 bb 4e 22 3c 6e 87}  //weight: 1, accuracy: High
        $x_1_2 = {cc ca ba 4e 2d c1 a6 4d 3a cf 56 35 92 3b 37 d5 cd c6 c6 b2 30 3c 06 66 6a 49 24 c0 b8 41 31 ce ad 32 4c 39 cc c8 cb cd cb bc 3b 39 c5 c9 be 41}  //weight: 1, accuracy: High
        $x_1_3 = {22 3c be 4c 3d c9 ac 3c 41 3a 36 cb ca cb cc bd 31 3c c6 c9 bb 4e 22 3c be 4c 3d c9 ac 3c 41 3a 36 cb ca cb cc bd 31 3c c6 c9 bb 4e 22 3c be 4c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_FormBook_EVA_2147821378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EVA!MTB"
        threat_id = "2147821378"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 02 08 1f 32 da 1f 32 d6 18 ?? ?? ?? ?? ?? 1f 10 ?? ?? ?? ?? ?? 84}  //weight: 1, accuracy: Low
        $x_1_2 = {02 11 04 91 07 61 06 09 91 61 13 05 08 11 04 11 05 d2 9c 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_USR_2147821518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.USR!MTB"
        threat_id = "2147821518"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 16 e0 00 00 0c 2b 16 20 d7 4a 55 4d 28 ?? ?? ?? 06 07 08 28 ?? ?? ?? 06 0b 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d df}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EVF_2147821543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EVF!MTB"
        threat_id = "2147821543"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "BCHGPA8EAF8SABC8XZTNK4" wide //weight: 1
        $x_1_2 = {5d 91 0a 06 ?? ?? ?? ?? ?? 03 04 5d ?? ?? ?? ?? ?? 61 0b 2b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EVG_2147821544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EVG!MTB"
        threat_id = "2147821544"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 02 8e 69 17 59 91 1f 70 61 13 04 02 8e 69 17 58}  //weight: 1, accuracy: High
        $x_1_2 = {02 07 91 11 04 61 09 06 91 61 13 05 08 07 11 05 d2 9c 06 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EVM_2147821946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EVM!MTB"
        threat_id = "2147821946"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 41 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 42 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 43 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 45 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 47 65 74 54 79 70 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 43 6f 6e 73 74 72 75 63 74 69 6f 6e 43 61 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EUX_2147822268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EUX!MTB"
        threat_id = "2147822268"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$E3768EFA-816C-42CA-851C-3A807A1B547F" ascii //weight: 1
        $x_1_2 = "Substring" ascii //weight: 1
        $x_1_3 = {00 47 65 74 4d 65 74 68 6f 64 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 47 65 74 50 69 78 65 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 54 6f 41 72 67 62 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 54 6f 49 6e 74 33 32 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 47 65 74 54 79 70 65 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EVO_2147822357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EVO!MTB"
        threat_id = "2147822357"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 03 07 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 06 07 91 61 d2 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d da}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EVO_2147822357_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EVO!MTB"
        threat_id = "2147822357"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 03 17 58 ?? ?? ?? ?? ?? 5d 91 0a 16 0b 02}  //weight: 1, accuracy: Low
        $x_1_2 = {00 53 41 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 54 48 41 49 30 30 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 54 48 41 49 30 32 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 47 65 74 54 79 70 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NL_2147822358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NL!MTB"
        threat_id = "2147822358"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 11 04 2c 0d 00 72 ?? ?? ?? ?? 28 ?? ?? ?? 0a 26 00 06 04 58 0d 08 09 59 04 5d 0b 02 03 7e ?? ?? ?? 04 5d 07 28 ?? ?? ?? 06 9c 02 13 05 2b 00 11 05 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {02 03 17 58 ?? ?? ?? ?? ?? 5d 91 0a 16 0b 02 03 28}  //weight: 1, accuracy: Low
        $x_1_3 = {20 16 f8 00 00 0c 2b 13 00 06 08 20 00 01 00 00 28 ?? ?? ?? ?? 0a 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NL_2147822358_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NL!MTB"
        threat_id = "2147822358"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {1f 10 28 e5 00 00 06 9c 11 05 20 05 60 ec 78 5a 20 9d 8b cb 32 61 38 50 ff ff ff 11 05 20 30 f3 e6 9a 5a 20 86 d2 1d 9c 61 38 3d ff ff ff 07 13 04 11 05 20 16 14 3e b6 5a 20 a8 fc db 2d 61 38 27 ff ff ff 08 18 58 0c 11 05 20 db 8e 0a 99 5a 20 73 be cb 32 61 38 10 ff ff ff 08 06 fe 04 0d 20 9d 6c 0b a0 38 01 ff ff ff 06 18 5b 8d 62 00 00 01 0b 11 05 20 df 10 fe 24 5a 20 cd 6f d2 94 61 38 e5 fe ff ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NL_2147822358_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NL!MTB"
        threat_id = "2147822358"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1a 5e 45 04 00 00 00 32 00 00 00 02 00 00 00 dc ff ff ff 1d 00 00 00 2b 30 02 02 7b 41 00 00 04 28 a3 00 00 06 06 20 6f 2c ad 05 5a 20 33 be 5e 53 61 2b c4}  //weight: 1, accuracy: High
        $x_1_2 = {20 b5 88 b2 41 61 25 0d 1a 5e 45 04 00 00 00 37 00 00 00 02 00 00 00 1f 00 00 00 dc ff ff ff 2b 35 07 08 30 08 20 16 b9 65 13 25 2b 06 20 fc 1f 01 55 25 26 09 20 ff 4e 0a 0b 5a 61 2b c2 06 16 07 28 6a 04 00 06 0a 09 20 46 7d 3d 58 5a 20 99 34 c6 7b 61 2b aa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NL_2147822358_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NL!MTB"
        threat_id = "2147822358"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "O59SCEHG8G48RR5AJQI454" wide //weight: 10
        $x_1_2 = "MD5CryptoServiceProvider" ascii //weight: 1
        $x_1_3 = "TripleDESCryptoServiceProvider" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
        $x_1_6 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NB_2147822359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NB!MTB"
        threat_id = "2147822359"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 08 02 08 18 5a 18 ?? ?? 00 00 0a 1f 10 28 7f 00 ?? ?? 9c 00 08 17 58 0c 08 06 fe 04 0d 09 2d de}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NB_2147822359_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NB!MTB"
        threat_id = "2147822359"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 55 a2 cb 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 68 00 00 00 12 00 00 00 3d 00 00 00 8b 01 00 00 4f 00 00 00 af 00 00 00 02 01 00 00 01 00 00 00 22 00 00 00 0a 00 00 00 2e 00 00 00 51}  //weight: 1, accuracy: High
        $x_1_2 = "-2e31cb1e4b6b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_WLG_2147822401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.WLG!MTB"
        threat_id = "2147822401"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lambweston.ga/g/" wide //weight: 1
        $x_1_2 = "powershell" wide //weight: 1
        $x_1_3 = "Start-Sleep -Seconds 18" wide //weight: 1
        $x_1_4 = "Reverse" ascii //weight: 1
        $x_1_5 = "GetResponseStream" ascii //weight: 1
        $x_1_6 = "WebRequest" ascii //weight: 1
        $x_1_7 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_USL_2147822404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.USL!MTB"
        threat_id = "2147822404"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 03 07 91 6f ?? ?? ?? 0a 00 00 07 25 17 59 0b 16 fe 02 0c 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EVP_2147822428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EVP!MTB"
        threat_id = "2147822428"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 11 04 91 07 61 06 ?? ?? ?? ?? ?? 09 91 61 13 05 1d 13 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {02 02 8e 69 17 59 91 1f 70 61 0b 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EVW_2147822927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EVW!MTB"
        threat_id = "2147822927"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 16 11 06 17 da 8c ?? ?? ?? 01 a2 14 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 09 11 06 09 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 da 13 07 11 04 11 07 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 04 11 06 17 d6 13 06}  //weight: 1, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = {86 06 20 00 86 06 20 00 86 06 20 00 86 06 20 00 86 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EVW_2147822927_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EVW!MTB"
        threat_id = "2147822927"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 4c 6f 6e 67 50 61 74 68 44 69 72 65 63 74 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 53 74 72 69 6e 67 54 79 70 65 49 6e 66 6f 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 49 6e 70 75 74 42 6c 6f 63 6b 53 69 7a 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 45 73 63 61 70 65 64 49 52 65 6d 6f 74 69 6e 67 46 6f 72 6d 61 74 74 65 72 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 78 31 30 00 70 72 6f 6a 65 63 74 6e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 4c 6f 77 65 73 74 42 72 65 61 6b 49 74 65 72 61 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 44 61 74 61 4d 69 73 61 6c 69 67 6e 65 64 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 44 69 72 65 63 74 6f 72 79 49 6e 66 6f 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 4f 41 41 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 45 6e 75 6d 43 61 74 65 67 6f 72 69 65 73 46 6c 61 67 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EVY_2147822928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EVY!MTB"
        threat_id = "2147822928"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HRHA5447E85NV455Q77OTA" ascii //weight: 1
        $x_1_2 = "Jinj" wide //weight: 1
        $x_1_3 = "ConstructionCall" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EVZ_2147822938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EVZ!MTB"
        threat_id = "2147822938"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c0 8c c8 8c 65 77 cf 30 cc 28 0c b8 80 08 88 b8 2b ea b0 28 a0 08 82 42 81 0d 6e 93 19 77 71 25 6a 34 0b 1a 4d 40 a3}  //weight: 1, accuracy: High
        $x_1_2 = {6d 6b cf 71 56 9c b3 74 75 db e9 4b d7 ac 71 d6 b7 9d 76 46 db 39 1b d6 b4 ad 5c d3 36 f3 98 13 da 56 3b cb ce e8 4a a7 cd f1 22 8d 63 67 49 d2}  //weight: 1, accuracy: High
        $x_1_3 = "GZipStream" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EVZ_2147822938_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EVZ!MTB"
        threat_id = "2147822938"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 4c 6f 6e 67 50 61 74 68 44 69 72 65 63 74 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 53 74 72 69 6e 67 54 79 70 65 49 6e 66 6f 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 49 6e 70 75 74 42 6c 6f 63 6b 53 69 7a 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 45 73 63 61 70 65 64 49 52 65 6d 6f 74 69 6e 67 46 6f 72 6d 61 74 74 65 72 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 78 31 30 00 70 72 6f 6a 65 63 74 6e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 4c 6f 77 65 73 74 42 72 65 61 6b 49 74 65 72 61 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 43 6c 6f 6e 65 48 65 6c 70 65 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 44 61 74 61 4d 69 73 61 6c 69 67 6e 65 64 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 44 69 72 65 63 74 6f 72 79 49 6e 66 6f 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 45 6e 75 6d 43 61 74 65 67 6f 72 69 65 73 46 6c 61 67 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EWA_2147822939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EWA!MTB"
        threat_id = "2147822939"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 00 74 00 72 00 00 09 69 00 6e 00 67 00 31}  //weight: 1, accuracy: High
        $x_1_2 = {86 06 20 00 86 06 20 00 86 06 20 00 86 06 20 00 86 06}  //weight: 1, accuracy: High
        $x_1_3 = {4c 00 65 00 6e 00 67 00 74 00 68 00 00 09 4c 00 6f 00 61 00 64}  //weight: 1, accuracy: High
        $x_1_4 = "GetString" wide //weight: 1
        $x_1_5 = "FromBase64" ascii //weight: 1
        $x_1_6 = "GetExportedTypes" ascii //weight: 1
        $x_1_7 = "GetMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EWE_2147823151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EWE!MTB"
        threat_id = "2147823151"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 11 05 06 11 05 06 ?? ?? ?? ?? ?? 5d ?? ?? ?? ?? ?? 09 11 05 91 61 d2 9c 00 11 05 17 58 13 05}  //weight: 1, accuracy: Low
        $x_1_2 = "FromBase64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EWE_2147823151_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EWE!MTB"
        threat_id = "2147823151"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 11 05 06 11 05 06 ?? ?? ?? ?? ?? 5d ?? ?? ?? ?? ?? 09 11 05 91 61 d2 9c 00 11 05 17 58 13 05}  //weight: 1, accuracy: Low
        $x_1_2 = "KLWO16UKQCU2APR" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_KNF_2147823554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.KNF!MTB"
        threat_id = "2147823554"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 73 83 00 00 0a 0d 09 20 00 01 00 00 6f ?? ?? ?? 0a 00 09 08 6f ?? ?? ?? 0a 00 09 18 6f ?? ?? ?? 0a 00 09 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a 13 04 11 04 28 ?? ?? ?? 06 74 7d 00 00 01 6f ?? ?? ?? 0a 17 9a 80 16 00 00 04 23 66 66 66 66 66 66 28 40}  //weight: 1, accuracy: Low
        $x_1_2 = "Jinj" wide //weight: 1
        $x_1_3 = "HRHA5447E85NV455Q77OTA" wide //weight: 1
        $x_1_4 = "THAI04" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EWG_2147823614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EWG!MTB"
        threat_id = "2147823614"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AFDYC54QHGFRR4F87GE5FX" ascii //weight: 1
        $x_1_2 = "TransformFinalBlock" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NG_2147823616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NG!MTB"
        threat_id = "2147823616"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5d 91 61 07 11 ?? 17 58 07 8e 69 5d 91}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NG_2147823616_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NG!MTB"
        threat_id = "2147823616"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 02 26 16 00 0f 00 28 ?? 00 00 06 25 26 0f 01 28 ?? 00 00 06 25 26 d0 01 00 00 1b 28 ?? 00 00 0a 25 26 28 ?? 00 00 0a 25 26 a5 01 00 00 1b 0a 38 00 00 00 00 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {57 b5 a2 3d 09 0f 00 00 00 00 00 00 00 00 00 00 01}  //weight: 1, accuracy: High
        $x_1_3 = "GetDelegateForFunctionPointer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EWK_2147823816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EWK!MTB"
        threat_id = "2147823816"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 00 03 05 1f 16 5d 6f ?? ?? ?? 0a 61 13 01}  //weight: 1, accuracy: Low
        $x_1_2 = {03 02 20 00 22 00 00 04 28 ?? ?? ?? 06 03 04 17 58 20 00 22 00 00 5d 91 28 ?? ?? ?? 0a 59 11 03 58 11 03 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EWN_2147823984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EWN!MTB"
        threat_id = "2147823984"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "75788555ZZZCU04BZDC584" ascii //weight: 1
        $x_1_2 = "TransformFinalBlock" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EWO_2147823985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EWO!MTB"
        threat_id = "2147823985"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YLKw8CA3QCAAACKAUAAAYLKwAHKgATMAIADQAA" wide //weight: 1
        $x_1_2 = "BwAABgoGLAtyWwAAcHMPAAAKegJ7AQAABAsrAA" wide //weight: 1
        $x_1_3 = "CausalitySource" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EWP_2147823986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EWP!MTB"
        threat_id = "2147823986"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 11 04 91 07 61 06 09 91 61 13 05 08 11 04 11 05 d2 9c 09 03 ?? ?? ?? ?? ?? 18 58 19 59}  //weight: 1, accuracy: Low
        $x_1_2 = {02 03 04 18 ?? ?? ?? ?? ?? 1f 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NO_2147824059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NO!MTB"
        threat_id = "2147824059"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 00 0f 00 28 ?? 00 00 06 25 26 0f 01 28 ?? 00 00 06 25 26 d0 01 00 00 1b 28 ?? 00 00 0a 25 26 28 17 00 00 0a 25 26 a5 01 00 00 1b 0a 38 00 00 00 00 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {57 b5 a2 3d 09 0f 00 00 00 00 00 00 00 00 00 00 02}  //weight: 1, accuracy: High
        $x_1_3 = "GetDelegateForFunctionPointer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EWR_2147824196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EWR!MTB"
        threat_id = "2147824196"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 00 74 00 72 00 00 09 69 00 6e 00 67 00 31}  //weight: 1, accuracy: High
        $x_1_2 = {86 06 20 00 86 06 20 00 86 06 20 00 86 06 20 00 86 06}  //weight: 1, accuracy: High
        $x_1_3 = "$3c6f829a-4484-4b9e-bf85-a09fd99a209f" ascii //weight: 1
        $x_1_4 = "GetExportedTypes" ascii //weight: 1
        $x_1_5 = "GetMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NY_2147824249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NY!MTB"
        threat_id = "2147824249"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 41 00 00 0a 26 11 0a 11 0d 16 11 0b 11 0c 16 6f ?? ?? ?? 0a 25 26 13 0f 7e ?? ?? ?? 04 11 0c 16 11 0f 6f ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "FGSTHDGFHJGJHD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NY_2147824249_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NY!MTB"
        threat_id = "2147824249"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Tefsdddddmp" ascii //weight: 1
        $x_1_2 = "C:\\NeddddddddddddddddddddddwTemp" ascii //weight: 1
        $x_1_3 = "DynamicDllInvokeType" ascii //weight: 1
        $x_1_4 = "dasdasddfdfhhdsdfsad" ascii //weight: 1
        $x_1_5 = "hThrehfdfhssddfad" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EWS_2147824457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EWS!MTB"
        threat_id = "2147824457"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 03 61 28 ?? ?? ?? 0a 0a 2b 00}  //weight: 1, accuracy: Low
        $x_1_2 = "K4DOM4DNGHSOE09" ascii //weight: 1
        $x_1_3 = "FromBase64" ascii //weight: 1
        $x_1_4 = "AetPalestinian" ascii //weight: 1
        $x_1_5 = "Rgrchart" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EWV_2147824459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EWV!MTB"
        threat_id = "2147824459"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "5XTOD5G4Q54GZ857BSC874" ascii //weight: 1
        $x_1_2 = "TransformFinalBlock" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EVX_2147824460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EVX!MTB"
        threat_id = "2147824460"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b7 a2 3d 09 0f 00 00 00 00 00 00 00 00 00 00 02}  //weight: 1, accuracy: High
        $x_1_2 = "$33fe5c32-db6a-4d7a-addc-e1d0d8588fb1" ascii //weight: 1
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "Tokenizer.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_CRWF_2147824714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.CRWF!MTB"
        threat_id = "2147824714"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 08 00 00 01 25 d0 15 00 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 73 7d 00 00 0a 0d 09 20 00 01 00 00 6f ?? ?? ?? 0a 09 08 6f ?? ?? ?? 0a 09 18 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a 13 04 11 04 28 ?? ?? ?? 06 74 35 00 00 01 6f ?? ?? ?? 0a 17 9a 80 2b 00 00 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EWH_2147824722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EWH!MTB"
        threat_id = "2147824722"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 4c 6f 6e 67 50 61 74 68 44 69 72 65 63 74 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 41 42 5a 4e 6f 64 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 41 75 64 69 74 46 6c 61 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 43 6f 6c 6c 65 63 74 69 6f 6e 4e 6f 64 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 46 69 6c 65 4e 6f 64 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 4c 6f 77 65 73 74 42 72 65 61 6b 49 74 65 72 61 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 43 6c 6f 6e 65 48 65 6c 70 65 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 46 69 6c 65 52 65 61 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 72 65 66 72 65 73 68 51 75 65 75 65 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 54 69 6d 65 53 70 61 6e 53 74 61 6e 64 61 72 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EWQ_2147824724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EWQ!MTB"
        threat_id = "2147824724"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 52 6f 6c 65 43 6c 61 69 6d 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 43 61 6c 65 6e 64 61 72 57 65 65 6b 52 75 6c 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 43 61 6e 54 69 6d 65 6f 75 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 44 69 63 74 69 6f 6e 61 72 79 45 6e 75 6d 65 72 61 74 6f 72 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 47 65 74 54 79 70 65 73 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 43 72 6f 73 73 53 69 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EWT_2147824725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EWT!MTB"
        threat_id = "2147824725"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 00 74 00 72 00 00 09 69 00 6e 00 67 00 31}  //weight: 1, accuracy: High
        $x_1_2 = {86 06 20 00 86 06 20 00 86 06 20 00 86 06 20 00 86 06}  //weight: 1, accuracy: High
        $x_1_3 = "GetExportedTypes" ascii //weight: 1
        $x_1_4 = "GetMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EWU_2147824726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EWU!MTB"
        threat_id = "2147824726"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$5a9e53f5-dfce-420d-9eeb-17dad89283e0" ascii //weight: 10
        $x_1_2 = "TransformFinalBlock" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "MD5CryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NI_2147824727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NI!MTB"
        threat_id = "2147824727"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 07 6f fd 00 00 0a 06 61 ?? ?? ?? ?? ?? 5a 0a 07 17 58 0b 07 02 6f e8 00 00 0a 2f 02 2b e1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NI_2147824727_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NI!MTB"
        threat_id = "2147824727"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 11 05 91 11 07 61 13 09 07 11 08 91 13 0a 02}  //weight: 5, accuracy: High
        $x_5_2 = {13 06 11 06 11 05 1f 16 5d 91 13 07 11 05 17 58 08 5d 13 08}  //weight: 5, accuracy: High
        $x_1_3 = "/DataSetA.xsd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NI_2147824727_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NI!MTB"
        threat_id = "2147824727"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 1c 00 00 01 0a 06 16 d0 1b 00 00 01 28 0f 00 00 0a a2 06 17 d0 1c 00 00 01 28 0f 00 00 0a a2 06 28 a2 00 00 0a 14 18 8d 14 00 00 01 0b 07 16 02 8c 1b 00 00 01 a2 07 17 03 a2 07 6f a3 00 00 0a 74 1f 00 00 01 2a}  //weight: 1, accuracy: High
        $x_1_2 = {b5 a2 3d 09 0f 00 00 00 00 00 00 00 00 00 00 01}  //weight: 1, accuracy: High
        $x_1_3 = "GetDelegateForFunctionPointer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_N_2147824728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.N!MTB"
        threat_id = "2147824728"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 04 06 08 06 91 11 05 06 11 05 6f 63 01 00 0a 5d 6f 93 01 00 0a 61 d2 9c 06 17 58 0a 06 08 8e 69}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_N_2147824728_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.N!MTB"
        threat_id = "2147824728"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$a2560ef8-b7df-47ae-af97-4954751fd232" ascii //weight: 1
        $x_1_2 = "DebuggableAttribute" ascii //weight: 1
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_N_2147824728_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.N!MTB"
        threat_id = "2147824728"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 29 01 00 70 02 03 28 ?? ?? 00 06 0c 12 02 28 ?? ?? 00 0a 28 ?? ?? 00 0a 28 ?? ?? 00 0a 00 38 ?? ?? 00 00 72 ?? ?? 00 70 02 03 28 ?? ?? 00 06 0c 12 02 28 ?? ?? 00 0a 28 ?? ?? 00 0a 28 ?? ?? 00 0a 00 38 ?? ?? 00 00 72 ?? ?? 00 70 02 03 28 ?? ?? 00 06 0c 12 02 28 ?? ?? 00 0a 28 ?? ?? 00 0a 28 ?? ?? 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "CollisionSimulation.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NZX_2147824732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NZX!MTB"
        threat_id = "2147824732"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "V5775R4O7AG9B589AD5H5C" ascii //weight: 1
        $x_1_2 = "Koolan" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "RijndaelManaged" ascii //weight: 1
        $x_1_5 = "GetObject" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_CEVC_2147824747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.CEVC!MTB"
        threat_id = "2147824747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 16 74 00 00 0c 2b 16 20 a4 d5 a6 6c 28 ?? ?? ?? 06 07 08 28 ?? ?? ?? 06 0b 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d df}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EXA_2147824791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EXA!MTB"
        threat_id = "2147824791"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0d 09 08 6f ?? ?? ?? 0a 09 18 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a 13 04 02}  //weight: 1, accuracy: Low
        $x_1_2 = "$2d144611-62c5-4eb8-a0ae-8a1617949dcc" ascii //weight: 1
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "MD5CryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EXB_2147824792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EXB!MTB"
        threat_id = "2147824792"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$13eb7ef6-db10-452e-8471-69e7ca2eee15" ascii //weight: 1
        $x_1_2 = {00 75 67 7a 31 00 75 67 7a 33 00 70 72 6f 6a 6e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 66 67 68 00 70 72 6f 6a 44 61 74 61 00 4b 31 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 78 79 7a 00 78 31 30 00 70 72 6f 6a 65 63 74 6e 61 6d 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NZT_2147824868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NZT!MTB"
        threat_id = "2147824868"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 00 0f 00 28 ?? 00 00 06 25 26 0f 01 28 ?? 00 00 06 [0-16] 00 00 0a 25 26 a5 01 00 00 1b 0a 38 00 00 00 00 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "GetDelegateForFunctionPointer" ascii //weight: 1
        $x_1_3 = "MTY5NC00ZjRhLTliZmYtZjIwNjAwZTM3OTg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EXD_2147824962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EXD!MTB"
        threat_id = "2147824962"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "775AH5FZFH07H4655FACFP" ascii //weight: 1
        $x_1_2 = "TransformFinalBlock" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EXE_2147824963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EXE!MTB"
        threat_id = "2147824963"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 02 8e 69 17 59 91 1f 70 61 0b}  //weight: 1, accuracy: High
        $x_1_2 = "$588CF8B1-6157-4CCE-9B26-EB41185918A3" ascii //weight: 1
        $x_1_3 = "NativeVariant.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NYA_2147825058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NYA!MTB"
        threat_id = "2147825058"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 00 0f 00 28 ?? 00 00 06 25 26 0f 01 28 ?? 00 00 06 25 26 d0 01 00 00 1b 28 ?? 00 00 0a 25 26 28 ?? 00 00 0a 25 26 a5 01 00 00 1b 0a 2b 00 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "mYtZjIwNjAwZT" ascii //weight: 1
        $x_1_3 = "GetDelegateForFunctionPointer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EXI_2147825272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EXI!MTB"
        threat_id = "2147825272"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CA4EU4J7TG4Y7B544H487O" ascii //weight: 10
        $x_10_2 = "IKMNJUHBVGYTFCXDRESZAWQ" ascii //weight: 10
        $x_1_3 = "GZipStream" ascii //weight: 1
        $x_1_4 = "CompressionMode" ascii //weight: 1
        $x_1_5 = "DebuggableAttribute" ascii //weight: 1
        $x_1_6 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_FormBook_EXJ_2147825273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EXJ!MTB"
        threat_id = "2147825273"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WeakTable.FileUtils" wide //weight: 1
        $x_1_2 = "CausalitySource" wide //weight: 1
        $x_1_3 = "FromBase64" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "GetMethod" ascii //weight: 1
        $x_1_6 = {00 45 73 63 61 70 65 64 49 52 65 6d 6f 74 69 6e 67 46 6f 72 6d 61 74 74 65 72 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 53 74 72 69 6e 67 54 79 70 65 49 6e 66 6f 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 49 6e 70 75 74 42 6c 6f 63 6b 53 69 7a 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABT_2147825449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABT!MTB"
        threat_id = "2147825449"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 14 0c 1e 8d ?? ?? ?? 01 0d 28 ?? ?? ?? 06 13 04 11 04 16 09 16 1e 28 ?? ?? ?? 0a 00 07 09 6f ?? ?? ?? 0a 00 07 18 6f ?? ?? ?? 0a 00 07 6f ?? ?? ?? 0a 13 05 11 05 06 16 06 8e 69 6f ?? ?? ?? 0a 0c 08}  //weight: 5, accuracy: Low
        $x_1_2 = "TransformFinalBlock" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "Y5tFvU8EY" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABT_2147825449_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABT!MTB"
        threat_id = "2147825449"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 b5 a2 3d 09 0f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 3d 00 00 00 1c 00 00 00 45 00 00 00 9c 00 00 00 c3 00 00 00 3f 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "MNVJDFHJDF.Properties.Resources.resources" ascii //weight: 1
        $x_1_5 = "$a689bf0c-ceb6-4895-8720-eeb3465536ef" ascii //weight: 1
        $x_1_6 = "Confuser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_GI_2147825451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.GI!MTB"
        threat_id = "2147825451"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {17 2d 06 d0 ?? ?? ?? 06 26 72 5b 00 00 70 0a 06 28 ?? ?? ?? 0a 25 26 0b 28 ?? ?? ?? 0a 25 26 07 16 07 8e 69 6f ?? ?? ?? 0a 0a 28 ?? ?? ?? 0a 25 26 06 6f ?? ?? ?? 0a 25 26 0c 1f 61 6a 08}  //weight: 10, accuracy: Low
        $x_1_2 = "TkJWWENNVlhDSktEJQ==" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ADT_2147825945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ADT!MTB"
        threat_id = "2147825945"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 16 e0 00 00 0c 2b 16 20 b3 f4 85 b5 28 ?? ?? ?? 06 07 08 28 ?? ?? ?? 06 0b 08 15 58 0c 08 16 fe 04 16 fe 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_BG_2147826388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.BG!MTB"
        threat_id = "2147826388"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {16 0b 2b 2d 02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? 00 00 0a 59 0d 03 08 09 28 ?? 00 00 06 03 08 09 28 ?? 00 00 06 03 04 28 ?? 00 00 06 07 17 58 0b 07 02 6f ?? 00 00 0a 32}  //weight: 3, accuracy: Low
        $x_2_2 = {02 03 16 61 04 16 60 6f ?? 00 00 0a 0a [0-4] 28 ?? 00 00 0a 16 61 28 ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_BG_2147826388_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.BG!MTB"
        threat_id = "2147826388"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "openvpn1\\openvpn1.exe" wide //weight: 1
        $x_1_2 = "hPfdsfhdsdrodscess" ascii //weight: 1
        $x_1_3 = "lpBasfsdsdfeddfhsAddress" ascii //weight: 1
        $x_1_4 = "fQUHbXDajcbuWkBrNgE3omtzLggrJJg9QDBRS2X14UMP0bI" wide //weight: 1
        $x_1_5 = "C:\\Tefsdddddmp" wide //weight: 1
        $x_1_6 = "C:\\NeddddddddddddddddddddddwTemp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EYC_2147826594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EYC!MTB"
        threat_id = "2147826594"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FPCDAC84E7D599FGY8G7KD" ascii //weight: 1
        $x_1_2 = "CompressionMode" ascii //weight: 1
        $x_1_3 = "GZipStream" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EYD_2147826595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EYD!MTB"
        threat_id = "2147826595"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 11 06 11 07 28 ?? ?? ?? 06 13 08 12 08 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 16 09 06 1a 28 ?? ?? ?? 06 00 06 1a 58 0a 00 11 07 17 58 13 07}  //weight: 1, accuracy: Low
        $x_1_2 = "EnumCategoriesFlags" ascii //weight: 1
        $x_1_3 = "DataMisaligned" ascii //weight: 1
        $x_1_4 = "LongPathDirectory" ascii //weight: 1
        $x_1_5 = "DirectoryInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ELFA_2147826855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ELFA!MTB"
        threat_id = "2147826855"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 16 f8 00 00 0b 2b 16 06 07 20 00 01 00 00 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 0a 07 15 58 0b 07 16 fe 04 16 fe 01 0c 08 2d df}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NC_2147826867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NC!MTB"
        threat_id = "2147826867"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 09 07 8e 69 5d 91 08 09 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 07 09 17 58 07 8e 69 5d 91 59}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NC_2147826867_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NC!MTB"
        threat_id = "2147826867"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PLMKOIJNBHUYGVGTYRFCRDFSEWZX" wide //weight: 1
        $x_1_2 = "System.Reflection.Assembly" wide //weight: 1
        $x_1_3 = "Lxxxad" wide //weight: 1
        $x_1_4 = "GZipStream" ascii //weight: 1
        $x_1_5 = "GetObject" ascii //weight: 1
        $x_1_6 = "GetTypes" ascii //weight: 1
        $x_1_7 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_UOM_2147826939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.UOM!MTB"
        threat_id = "2147826939"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DownloadData" ascii //weight: 1
        $x_1_2 = "01101000011101000111010001110000001110100010111100" wide //weight: 1
        $x_1_3 = "10111100111000001101010010111000110010001100000011" wide //weight: 1
        $x_1_4 = "UnescapedXmlDiagnosticData" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "ToString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EYF_2147826946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EYF!MTB"
        threat_id = "2147826946"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "B8D25T" wide //weight: 1
        $x_1_2 = "Paretherflen.Tucson" wide //weight: 1
        $x_1_3 = "CompressionMode" ascii //weight: 1
        $x_1_4 = "GZipStream" ascii //weight: 1
        $x_1_5 = "DebuggableAttribute" ascii //weight: 1
        $x_1_6 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EYJ_2147827079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EYJ!MTB"
        threat_id = "2147827079"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YUG54G5EA" wide //weight: 1
        $x_1_2 = {00 4d 65 73 73 61 67 65 00 50 72 6f 70 65 72 74 69 65 73 00}  //weight: 1, accuracy: High
        $x_1_3 = "CompressionMode" ascii //weight: 1
        $x_1_4 = "GZipStream" ascii //weight: 1
        $x_1_5 = "DebuggableAttribute" ascii //weight: 1
        $x_1_6 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EYL_2147827196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EYL!MTB"
        threat_id = "2147827196"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ncjhdsfu" wide //weight: 1
        $x_1_2 = "pjdfsgyufiujg" wide //weight: 1
        $x_1_3 = "xckjvbvigforg" wide //weight: 1
        $x_1_4 = "zLzozazdz" wide //weight: 1
        $x_1_5 = "InvokeMember" wide //weight: 1
        $x_1_6 = "DMDeDtDhDoDdD0D" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_FES_2147827637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.FES!MTB"
        threat_id = "2147827637"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 47 03 06 03 8e 69 5d 91 61 d2 52 06 1b 2c e3 17 58 1e 2d 12 26 06 02 8e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NYP_2147828069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NYP!MTB"
        threat_id = "2147828069"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 07 09 07 8e 69 5d 91 06 09 91 61 d2 2b 06 09 17 58 0d 2b 07 6f}  //weight: 1, accuracy: High
        $x_1_2 = "filthy-regret.dvrlists.c" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_QSM_2147828106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.QSM!MTB"
        threat_id = "2147828106"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 09 07 09 07 8e 69 5d 91 06 09 91 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_KXFA_2147828205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.KXFA!MTB"
        threat_id = "2147828205"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 19 8d 10 00 00 01 25 16 09 a2 25 17 16 8c ?? ?? ?? 01 a2 25 18 11 05 8c ?? ?? ?? 01 a2 28 ?? ?? ?? 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "GZipStream" ascii //weight: 1
        $x_1_3 = "CompressionMode" ascii //weight: 1
        $x_1_4 = "G4G15" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_OEJ_2147828288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.OEJ!MTB"
        threat_id = "2147828288"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 0e 11 0f 9a 13 05 07 11 05 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 13 06 06 11 06 6f ?? ?? ?? 0a 11 0f 17 58 13 0f 11 0f 11 0e 8e 69 32 d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_KWFA_2147828292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.KWFA!MTB"
        threat_id = "2147828292"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e fd 01 00 04 73 cb 03 00 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 74 55 01 00 1b 0a 73 cd 03 00 0a 0b 07 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 73 cf 03 00 0a 0d 09 08 6f ?? ?? ?? 0a 00 09 18 6f ?? ?? ?? 0a 00 09 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a 13 04 11 04 17 28 ?? ?? ?? 06 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 1f 0b 9a 80 fc 01 00 04}  //weight: 1, accuracy: Low
        $x_1_2 = "ComputeHash" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_QTM_2147828293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.QTM!MTB"
        threat_id = "2147828293"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 16 00 00 01 0d 16 13 04 2b 22 09 11 04 08 11 04 08 8e 69 5d 91 06 11 04 91 61 d2 9c 2b 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_DTM_2147828294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.DTM!MTB"
        threat_id = "2147828294"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 20 c0 0f 00 00 28 ?? ?? ?? 0a 72 05 00 00 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 0b 72 4e 03 00 70 28 ?? ?? ?? 06 0c 06 07}  //weight: 1, accuracy: Low
        $x_1_2 = "XmlNamespaceEncoder" wide //weight: 1
        $x_1_3 = "DefineByValTStrRemotingServices" ascii //weight: 1
        $x_1_4 = "Split" ascii //weight: 1
        $x_1_5 = "InvokeMember" ascii //weight: 1
        $x_1_6 = "GetType" ascii //weight: 1
        $x_1_7 = "WebClient" ascii //weight: 1
        $x_1_8 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MVM_2147828421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MVM!MTB"
        threat_id = "2147828421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 01 00 00 70 02 09 18 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 03 11 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6a 61 69 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 07 06 11 07 6f ?? ?? ?? 0a 26 11 04 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABE_2147828470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABE!MTB"
        threat_id = "2147828470"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 bd 02 3e 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 48 00 00 00 2f 00 00 00 5e 00 00 00 12 01 00 00 34 01 00 00}  //weight: 5, accuracy: High
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
        $x_1_4 = "get_CurrentDomain" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "pbDebuggerPresent" ascii //weight: 1
        $x_1_7 = "GetRuntimeDirectory" ascii //weight: 1
        $x_1_8 = "Confuser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABX_2147828474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABX!MTB"
        threat_id = "2147828474"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 9d a2 29 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 7c 00 00 00 57 00 00 00 8f 02 00 00 ea 02 00 00 db 02 00 00}  //weight: 2, accuracy: High
        $x_1_2 = "ShortAndLongKeyword" ascii //weight: 1
        $x_1_3 = "GetTempFileName" wide //weight: 1
        $x_1_4 = "HHMHeHHHtHHHhHHHoHHHdHH0HH" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_FM_2147828533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.FM!MTB"
        threat_id = "2147828533"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 08 11 04 08 8e 69 5d 91 06 11 04 91 61 d2 6f ?? ?? ?? 0a 11 04 17 58 13 04 11 04 06 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_SYES_2147828569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.SYES!MTB"
        threat_id = "2147828569"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 0d 07 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 04 11 04 16 09 16 1f 10 28 ?? ?? ?? 0a 11 04 16 09 1f 0f 1f 10 28 ?? ?? ?? 0a 06 09 6f ?? ?? ?? 0a 06 18 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 13 05 02 28 ?? ?? ?? 0a 13 06 28 ?? ?? ?? 0a 11 05 11 06 16 11 06 8e 69 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a}  //weight: 2, accuracy: Low
        $x_1_2 = "IAsyncLocal" ascii //weight: 1
        $x_1_3 = "ComputeHash" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_IZFA_2147828662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.IZFA!MTB"
        threat_id = "2147828662"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 06 08 06 08 8e 69 5d 91 07 06 91 61 d2}  //weight: 2, accuracy: High
        $x_1_2 = "GetBytes" ascii //weight: 1
        $x_1_3 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABL_2147828764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABL!MTB"
        threat_id = "2147828764"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 1d a2 09 09 01 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 70 00 00 00 0b 00 00 00 89 00 00 00 50 00 00 00 52 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = "TransformFinalBlock" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "PASSWORD" wide //weight: 1
        $x_1_5 = "Your_Friend_The_Rat_icon" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_FK_2147829038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.FK!MTB"
        threat_id = "2147829038"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 13 09 11 07 13 0a 11 09 11 0a 3d 32 00 00 00 02 08 17 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 09 20 b3 15 00 00 5d 59 13 0b 11 08 11 0b 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 08 08 17 58 0c 2b be}  //weight: 2, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "ToString" ascii //weight: 1
        $x_1_5 = "WebClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_LXM_2147829117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.LXM!MTB"
        threat_id = "2147829117"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 08 03 6f ?? ?? ?? 0a 5d 17 58 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 59 13 04 06 11 04 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 08 17 58 0c 08 09 31 c1}  //weight: 2, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "ToString" ascii //weight: 1
        $x_1_5 = "WebClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_SHC_2147829134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.SHC!MTB"
        threat_id = "2147829134"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {17 8d 17 00 00 01 25 16 07 a2 25 0c 14 14 17 8d ?? ?? ?? 01 25 16 17 9c 25 0d 28 ?? ?? ?? 0a 09 16 91 2d 02 2b 09 08 16 9a 28 ?? ?? ?? 0a 0b 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 26 07 28 ?? ?? ?? 0a}  //weight: 2, accuracy: Low
        $x_1_2 = "StonksRound.GameEndStats" wide //weight: 1
        $x_1_3 = "KLAXD DSHSADJUFAHGYF XUYFG" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_BCMY_2147829244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.BCMY!MTB"
        threat_id = "2147829244"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 07 20 63 68 db 3e 28 ?? ?? ?? 06 28 ?? ?? ?? 06 74 0b 00 00 1b 6f ?? ?? ?? 0a 0c 73 7b 00 00 0a 0d 09 08 6f ?? ?? ?? 0a 09 18 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a 13 04 11 04 03 28 ?? ?? ?? 06 28 ?? ?? ?? 06 20 76 68 db 3e 28 ?? ?? ?? 06 6f ?? ?? ?? 0a}  //weight: 2, accuracy: Low
        $x_1_2 = "ComputeHash" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABS_2147829258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABS!MTB"
        threat_id = "2147829258"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 09 16 20 ?? ?? ?? 00 6f ?? ?? ?? 0a 13 05 11 05 16 fe 02 13 06 11 06 2c 2d 00 11 04 72 ?? ?? ?? 70 18 19 8d ?? ?? ?? 01 25 16 09 a2 25 17 16 8c ?? ?? ?? 01 a2 25 18 11 05 8c ?? ?? ?? 01 a2 28 ?? ?? ?? 0a 26 00 00 11 05 16 fe 02 13 07 11 07 2d ac 11 04 6f ?? ?? ?? 0a 0b 00 de 0d}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "GZipStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABS_2147829258_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABS!MTB"
        threat_id = "2147829258"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 95 a2 29 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 49 00 00 00 15 00 00 00 3c 00 00 00 5c 00 00 00 4c 00 00 00}  //weight: 5, accuracy: High
        $x_1_2 = "get_IsAttached" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
        $x_1_5 = "GetResponseStream" ascii //weight: 1
        $x_1_6 = "get_CurrentDomain" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
        $x_1_8 = "Confuser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_STG_2147829273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.STG!MTB"
        threat_id = "2147829273"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 11 04 91 07 61 06 09 91 61 13 05 08 11 04 11 05 d2 9c 09 03 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MVH_2147829343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MVH!MTB"
        threat_id = "2147829343"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 14 00 00 04 73 40 00 00 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 0a 73 42 00 00 0a 0b 07 72 ?? ?? ?? 70 28 ?? ?? ?? 06 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 0c 73 44 00 00 0a 0d 09 08 6f ?? ?? ?? 0a 00 09 18 6f ?? ?? ?? 0a 00 09 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a}  //weight: 2, accuracy: Low
        $x_1_2 = "Fabraka" wide //weight: 1
        $x_1_3 = "T5AAZ" wide //weight: 1
        $x_1_4 = "ComputeHash" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RYM_2147829491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RYM!MTB"
        threat_id = "2147829491"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 07 03 6f ?? ?? ?? 0a 5d 17 58 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 59 0d 06 09 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 07 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NX_2147829819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NX!MTB"
        threat_id = "2147829819"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {05 0e 04 06 58 03 04 06 58 91 9c 06 17 58 0a 06 0e 05 32 ec 2a}  //weight: 5, accuracy: High
        $x_4_2 = {06 07 02 7b ?? 00 00 04 07 94 9e 07 17 58 0b 07 02}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NX_2147829819_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NX!MTB"
        threat_id = "2147829819"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$6bff7332-11b4-47ea-9cc6-26d29ee43246" ascii //weight: 1
        $x_1_2 = "TheQuest.Properties.Resources.resources" ascii //weight: 1
        $x_1_3 = "FromBase64" ascii //weight: 1
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NLY_2147829833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NLY!MTB"
        threat_id = "2147829833"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$912efa92-610b-40f2-a282-22d1b6f64e01" ascii //weight: 1
        $x_1_2 = {57 9d a2 29 09 0b 00 00 00 fa 01 33 00 16 00 00 01}  //weight: 1, accuracy: High
        $x_1_3 = "BLL.Properties.Resources" ascii //weight: 1
        $x_1_4 = "p0.jO" ascii //weight: 1
        $x_1_5 = "LogSwitch" ascii //weight: 1
        $x_1_6 = "XCCVV" ascii //weight: 1
        $x_1_7 = "Panda" ascii //weight: 1
        $x_1_8 = "CreateDecryptor" ascii //weight: 1
        $x_1_9 = "TransformFinalBlock" ascii //weight: 1
        $x_1_10 = "RijndaelManaged" ascii //weight: 1
        $x_1_11 = "GetDomain" ascii //weight: 1
        $x_1_12 = "SHA256CryptoServiceProvide" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NBGA_2147829915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NBGA!MTB"
        threat_id = "2147829915"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fabraka" wide //weight: 1
        $x_1_2 = "T5AAZ" wide //weight: 1
        $x_1_3 = "ComputeHash" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
        $x_1_6 = "Lt.LE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABV_2147829924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABV!MTB"
        threat_id = "2147829924"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 15 02 00 09 08 00 00 00 00 00 00 00 00 00 00 01 00 00 00 2d 00 00 00 06 00 00 00 6e 00 00 00 13 00 00 00 02 00 00 00 2e 00 00 00}  //weight: 5, accuracy: High
        $x_1_2 = "Yvvqr.exe" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "GetResponseStream" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ZYM_2147829990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ZYM!MTB"
        threat_id = "2147829990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 11 06 07 06 07 91 20 ?? ?? ?? 00 59 d2 9c 07 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NXE_2147830014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NXE!MTB"
        threat_id = "2147830014"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$2b6b1c23-980d-45a9-860c-4785da365ad2" ascii //weight: 1
        $x_1_2 = {57 9f a2 2b 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 92 00 00 00 28 00 00 00 6f 00 00 00 a5}  //weight: 1, accuracy: High
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
        $x_1_5 = "RijndaelManaged" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NXD_2147830015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NXD!MTB"
        threat_id = "2147830015"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$7ea43059-feaa-4bbd-8d12-0a769525d21e" ascii //weight: 1
        $x_1_2 = "Shotgun.Properties.Resources.resources" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_UBN_2147830017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.UBN!MTB"
        threat_id = "2147830017"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 2c 01 00 70 28 ?? ?? ?? 0a 13 07 28 ?? ?? ?? 0a 11 07 6f ?? ?? ?? 0a 13 08 11 06 11 08 11 04 6f ?? ?? ?? 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "DownloadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MEGA_2147830068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MEGA!MTB"
        threat_id = "2147830068"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 ad 07 00 70 6f ?? ?? ?? 0a 74 05 00 00 1b 0a 28 ?? ?? ?? 0a 72 b7 07 00 70 6f ?? ?? ?? 0a 1e 8d 5a 00 00 01 17 73 72 00 00 0a 0b 73 73 00 00 0a 0c 08 07 1f 10 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 07 1f 10 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a}  //weight: 2, accuracy: Low
        $x_1_2 = "Ruby" wide //weight: 1
        $x_1_3 = "55R7SPC4B54JQGN4C547H4" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_LCN_2147830186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.LCN!MTB"
        threat_id = "2147830186"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetFolderPath" ascii //weight: 1
        $x_1_2 = "DownloadFile" ascii //weight: 1
        $x_1_3 = "ReliabilityContractAttribute" wide //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "37.139.129.142" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ZBN_2147830209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ZBN!MTB"
        threat_id = "2147830209"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 2b 03 0b 2b 00 2b 3b 2b 3c 72 ?? ?? ?? 70 2b 3c 2b 41}  //weight: 1, accuracy: Low
        $x_1_2 = {26 1c 2c 0d 2b 3f 2b 40 2b 41 06 18 6f ?? ?? ?? 0a 02 0d 06 6f ?? ?? ?? 0a 09 16 09 8e 69 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NXK_2147830419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NXK!MTB"
        threat_id = "2147830419"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wahhhhhhhnt to delete is not exist" ascii //weight: 1
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "C:\\soggsssssgggggggmedirectory" ascii //weight: 1
        $x_1_4 = "FromBase64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_CEN_2147830475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.CEN!MTB"
        threat_id = "2147830475"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WebClient" ascii //weight: 1
        $x_1_2 = "RightsManagementEncryptedStream.SafeNativeCompoundFileConstants" wide //weight: 1
        $x_1_3 = "DesignerSerializationOptionsAttribute" wide //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "37.139.129.142" wide //weight: 1
        $x_1_7 = "RightsManagementEncryptedStream" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_HWD_2147830493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.HWD!MTB"
        threat_id = "2147830493"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 6f 00 00 04 28 ?? ?? ?? 0a 0a 17 72 b5 14 00 70 28 ?? ?? ?? 06 0b 73 a8 00 00 0a 0c 08 1f 10 07 28 ?? ?? ?? 06 74 07 00 00 1b 6f ?? ?? ?? 0a 00 08 1f 10 07 28 ?? ?? ?? 06 74 07 00 00 1b 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 06 16 06 8e 69 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "57H3FNPC54JHXFFF8DC347" wide //weight: 1
        $x_1_4 = "BullsAndCowsUI" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NXP_2147830736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NXP!MTB"
        threat_id = "2147830736"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 82 08 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 16 07 16 1e 28 ?? 00 00 0a 25 07 6f ?? 00 00 0a 25 18}  //weight: 1, accuracy: Low
        $x_1_2 = "sk41Ua2AFu5PANMKit.abiJPmfBfTL6iLfmaW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_GHGA_2147830749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.GHGA!MTB"
        threat_id = "2147830749"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 7f 02 00 70 6f ?? ?? ?? 0a 74 01 00 00 1b 0a 73 42 00 00 0a 0b 73 43 00 00 0a 0c 14 0d 1e 8d 42 00 00 01 13 04 08 1b 8d 42 00 00 01 25 d0 b2 00 00 04}  //weight: 2, accuracy: Low
        $x_1_2 = "Kulibing" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NXQ_2147830825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NXQ!MTB"
        threat_id = "2147830825"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sk41Ua2AFu5PANMKit.abiJPmfBfTL6iLfmaW" ascii //weight: 1
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ITZF_2147830962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ITZF!MTB"
        threat_id = "2147830962"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 09 11 04 6f ?? ?? ?? 0a 13 05 08 09 11 04 6f ?? ?? ?? 0a 13 06 11 06 28 ?? ?? ?? 0a 13 07 07 06 11 07}  //weight: 2, accuracy: Low
        $x_1_2 = "Aeeee" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MFP_2147831072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MFP!MTB"
        threat_id = "2147831072"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 11 04 91 07 61 06}  //weight: 1, accuracy: High
        $x_1_2 = {08 11 04 11 05 d2 9c 09 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RJGA_2147831192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RJGA!MTB"
        threat_id = "2147831192"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 06 07 6f ?? ?? ?? 0a 26 08 06 07 6f ?? ?? ?? 0a 13 05 11 05 28 ?? ?? ?? 0a 13 06 11 04 09 11 06 d2 9c 07 17 58 0b 07 08 6f ?? ?? ?? 0a fe 04 13 07 11 07 2d ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_BZH_2147831289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.BZH!MTB"
        threat_id = "2147831289"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 14 0c 1e 8d ?? ?? ?? 01 0d 28 ?? ?? ?? 06 13 04 11 04 16 09 16 1e 28 ?? ?? ?? 0a}  //weight: 2, accuracy: Low
        $x_1_2 = "Kulibing" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_OLB_2147831290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.OLB!MTB"
        threat_id = "2147831290"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 63 00 00 04 72 7d 3d 00 70 72 81 3d 00 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 0b 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 14 72 87 3d 00 70 7e 46 01 00 0a 72 8d 3d 00 70 28}  //weight: 2, accuracy: Low
        $x_1_2 = "Clinic" wide //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_OHN_2147831292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.OHN!MTB"
        threat_id = "2147831292"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 09 07 09 07 8e 69 5d 91 03 09 91 61 d2 9c 09 17 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_HXZF_2147831356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.HXZF!MTB"
        threat_id = "2147831356"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 09 11 04 28 ?? ?? ?? 06 13 05 08 09 11 04 6f ?? ?? ?? 0a 13 06 11 06 28 ?? ?? ?? 0a 13 07 07 06 11 07 d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 08 11 08 2d c8}  //weight: 2, accuracy: Low
        $x_1_2 = "SandboxDotNet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_PKGA_2147831368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.PKGA!MTB"
        threat_id = "2147831368"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 05 08 09 11 04 6f ?? ?? ?? 0a 13 06 11 06 28 ?? ?? ?? 0a 13 07 07 06 11 07 d2 9c 00 11 04 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "BlackHawkDown" wide //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABN_2147831437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABN!MTB"
        threat_id = "2147831437"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0a 20 00 32 ?? 00 8d ?? ?? ?? 01 0b 28 ?? ?? ?? 06 0c 16 0d 2b 50 00 16 13 04 2b 31 00 08 09 11 04 6f ?? ?? ?? 0a 13 05 08 09 11 04 6f ?? ?? ?? 0a 13 06 11 06 28 ?? ?? ?? 0a 13 07 07 06 11 07 28 ?? ?? ?? 0a 9c 00 11 04 17 58 13 04 11 04 08 6f ?? ?? ?? 0a fe 04 13 08 11 08 2d bf}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "Y5tFvU8EY" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ALGA_2147831466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ALGA!MTB"
        threat_id = "2147831466"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 13 05 08 09 11 04 6f ?? ?? ?? 0a 13 06 11 06 28 ?? ?? ?? 0a 13 07 07 06 11 07 d2 9c 00 11 04 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "LuminousForts" wide //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MLGA_2147831558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MLGA!MTB"
        threat_id = "2147831558"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 09 11 04 28 ?? ?? ?? 06 13 05 08 09 11 04 6f ?? ?? ?? 0a 13 06 11 06 28 ?? ?? ?? 0a 13 07 07 06 11 07 d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 08 11 08 2d c8 06 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "GreenPixelsCalculator" wide //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AWX_2147832036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AWX!MTB"
        threat_id = "2147832036"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 09 11 04 28 ?? ?? ?? 06 13 05 11 05 28 ?? ?? ?? 06 13 06 07 06 11 06 d2 9c 00 11 04 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "Ambry" wide //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ADBI_2147832251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ADBI!MTB"
        threat_id = "2147832251"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 11 04 28 ?? ?? ?? 06 13 05 11 05 28 ?? ?? ?? 06 13 06 07 06 11 06 d2 9c 00 11 04 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "CoreAssign" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 0c 07 11 0b 91 59 11 0d 58 11 0d 5d 13 0e 07 11 09 11 0e d2 9c 11 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 0a 11 0a 11 06 1f 16 5d 91 13 0b 11 04 11 06 91 11 0b 61 13 0c 11 06 18 58 17 59 11 05 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 13 05 11 05 28 ?? ?? ?? 06 13 06 07 06 11 06 d2 9c 00 11 04 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "Sky" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0b 16 0c 2b 15 00 06 08 03 08 91 07 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 04 8e 69 fe 04 0d 09 2d e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 10 62 12 00 28 ?? 00 00 0a 1e 62 60 12 00 28 ?? 00 00 0a 60 0c 03 08 1f 10 63 20 ff 00 00 00 5f d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {91 61 07 11 07 20 c0 e1 00 00 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 06 17 58 0a 06 20 c0 e1 00 00 fe 04 13 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 13 04 16 2d f8 2b 19 11 04 1e 25 2c e1 62 13 04 11 04 06 07 25 17 59 0b 91 58 13 04 09 17 59 0d 18 39 78 00 00 00 09 2d de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 05 2b 46 00 07 11 05 07 8e 69 5d 07 11 05 07 8e 69 5d 91 08 11 05 1f 16 5d 91 61 28 ?? 00 00 0a 07 11 05 17 58 07 8e 69 5d 91 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 09 07 8e 69 5d 02 07 09 07 8e 69 5d 91 08 09 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 28 ?? 00 00 0a 07 09 17 58 07 8e 69 5d 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 07 16 13 08 2b 26 16 13 09 28 ?? 00 00 0a 13 0d 12 0d 28 ?? 00 00 0a 11 09 2f 0b 09 13 0a 11 0a 28 ?? 00 00 06 26 11 08 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 18 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 06 02 7b 04 00 00 04 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 0b 07 03 16 03 8e 69 6f ?? ?? ?? 0a 0c 08 0d de 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 11 0f 58 19 5d 13 11 18 11 0f 58 19 5d 13 12 19 8d ?? 00 00 01 13 13 11 13 16 12 0c 28 ?? 00 00 0a 9c 11 13 17 12 0c 28 ?? 00 00 0a 9c 11 13 18 12 0c 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 08 8e 69 6a 5d d4 91 58 11 04 11 06 95 58 20 ff 00 00 00 5f 13 07 02 11 04 11 06 8f ?? 00 00 01 11 04 11 07 8f ?? 00 00 01 28 ?? 00 00 06 00 11 06 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 2b 3a 06 09 5d 13 05 06 17 58 09 5d 13 0a 07 11 0a 91 ?? ?? ?? ?? ?? 58 13 0b 07 11 05 91 13 0c 07 11 05 11 0c 11 06 06 1f 16 5d 91 61 11 0b 59 ?? ?? ?? ?? ?? 5d d2 9c 06 17 58 0a 06 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 08 2b 3a 11 07 11 06 6f ?? 00 00 0a 13 04 11 04 28 ?? 00 00 0a 13 05 11 05 6c 03 28 ?? 00 00 0a 59 28 ?? 00 00 0a b7 0a 06 28 ?? 00 00 0a 0c 07 08 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 91 1d 59 1f 09 59 d2 0b 07 06 02 07 9c 2a}  //weight: 1, accuracy: High
        $x_2_2 = {17 59 0a 2b 1e 02 03 06 6f ?? 00 00 0a 93 0b 02 03 06 6f ?? 00 00 0a 02 06 93 9d 02 06 07 9d 06 17 59 0a 06 16 2f de}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0b 2b 3a 06 07 06 8e 69 5d 06 07 06 8e 69 5d 91 11 04 07 1f 16 5d 91 61 06 07 17 58 06 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? 00 00 0a 9c 07 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 05 16 8c ?? 00 00 01 19 8d ?? 00 00 01 25 16 08 16 9a a2 25 17 08 17 9a a2 25 18 20 93 c8 2a 2a 28 ?? 00 00 2b a2 13 0f 11 0f 28}  //weight: 2, accuracy: Low
        $x_1_2 = "thinkgear_form" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_18
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 11 07 11 08 6f ?? 00 00 0a 13 09 12 09 28 ?? 00 00 0a 16 61 d2 13 0a 12 09 28 ?? 00 00 0a 16 61 d2 13 0b 12 09 28 ?? 00 00 0a 16 61 d2 13 0c 07 11 0a 6f ?? 00 00 0a 08 11 0b 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_19
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0a 16 0b 18 0d 2b d6 02 07 06 03 04 28 ?? 00 00 06 0a 07 17 58 0b 18 0d 2b c3}  //weight: 2, accuracy: Low
        $x_1_2 = {11 05 17 58 20 ff 00 00 00 5f 13 05 11 06 11 04 75 ?? 00 00 1b 11 05 95 58 20 ff 00 00 00 5f 13 06 1f 1c 13 12}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_20
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 11 09 95 11 06 11 0a 95 58 20 ff 00 00 00 5f 13 10 11 07 13 11 09 11 11 91 13 12 11 06 11 10 95 13 13 11 12 11 13 61 13 14 11 05 11 11 11 14 d2 9c 11 07 17 58}  //weight: 2, accuracy: High
        $x_1_2 = "AutoNajam" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_21
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 06 2b 3d 00 09 11 06 11 05 6f ?? 00 00 0a 17 59 2e 18 11 05 11 06 6f ?? 00 00 0a 08 11 06 6f ?? 00 00 0a 6f ?? 00 00 0a 2b 09 11 05 11 06 6f ?? 00 00 0a 6f ?? 00 00 0a 26 00 11 06 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_22
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 08 91 13 0b 20 00 01 00 00 13 0c 11 0b 08 11 09 91 61 07 11 0a 91 59 11 0c 58 11 0c 5d 13 0d 07 11 08 11 0d d2 9c 00 11 07 17 58 13 07}  //weight: 2, accuracy: High
        $x_1_2 = "QuanLyThuVien.QuanLyThanhVien" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_23
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 16 0b 2b 12 02 07 07 61 07 61 03 04 28 ?? 00 00 06 00 07 17 58 0b 07 06 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 0c 08}  //weight: 3, accuracy: Low
        $x_2_2 = {16 0a 2b 12 02 06 06 06 5f 60 91 04 28 ?? 00 00 06 00 06 17 58 0a 06 03 03 61 03 61 fe 04 0b 07 2d e2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_24
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 13 0a 2b 59 00 20 00 01 00 00 13 0b 11 0a 17 58 13 0c 11 0a 20 00 56 01 00 5d 13 0d 11 0c 20 00 56 01 00 5d 13 0e 11 04 11 0e 91 11 0b 58 13 0f 11 04 11 0d 91 13 10 11 05 11 0a 1f 16 5d 91 13 11 11 10 11 11 61 13 12 11 04 11 0d 11 12 11 0f 59 11 0b 5d d2 9c 00 11 0a 17 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_25
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 04 03 6f ?? 00 00 0a 59 0d 09 19 fe 04 16 fe 01 13 05 11 05 2c 2f 00 03 19 8d ?? 00 00 01 25 16 12 02 28 ?? 00 00 0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 02 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 00 2b 4c 09 16 fe 02 13 06 11 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_26
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 01 00 00 14 14 19 8d ?? ?? ?? 01 25 16 06 6f ?? ?? ?? 0a a2 25 17 16 8c ?? ?? ?? 01 a2 25 18 06 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 16 0b 02 6f ?? 00 00 0a 17 59 0c 2b 18 00 06 07 93 0d 06 07 06 08 93 9d 06 08 09 9d 07 17 58 0b 08 17 59 0c 00 07 08 fe 04 13 04 11 04 2d de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_27
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 06 2b 69 00 02 09 11 06 28 ?? 00 00 06 13 07 02 11 06 08 28 ?? 00 00 06 13 08 02 07 11 08 08 28 ?? 00 00 06 13 09 02 07 11 06 08 11 07 11 09 28 ?? 00 00 06 13 0a 02 11 0a 28}  //weight: 2, accuracy: Low
        $x_1_2 = "JapaneseTrainer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_28
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 05 06 6f ?? 00 00 0a 0b 03 6f ?? 00 00 0a 0c 04 08 59 0d 09 16 30 03 16 2b 01 17 13 04 08 19 58 04 fe 02 16 fe 01 13 05 11 05 2c 07 11 04 17 fe 01 2b 01 16 13 06 11 06 2c 0f 00 03 07}  //weight: 2, accuracy: Low
        $x_1_2 = "MyPaint.Editor.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_29
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "listaAmizades" ascii //weight: 1
        $x_1_2 = "GravarAmizades" ascii //weight: 1
        $x_1_3 = "GerarArquivoMatchAmizades" ascii //weight: 1
        $x_1_4 = "TratarExcecaoArquivo" ascii //weight: 1
        $x_1_5 = "AmigoSecretoWinForms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_30
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 08 58 08 5d 13 0b 16 13 17 2b 29 00 11 17 13 19 11 19 13 18 11 18 2c 09 2b 00 11 18 17 2e 08 2b 0c 11 0b 13 0b 2b 06 11 0b 13 0b 2b 00 00 11 17 17 58 13 17 11 17 18 fe 04}  //weight: 1, accuracy: High
        $x_1_2 = {16 13 1b 2b 29 00 11 1b 13 1d 11 1d 13 1c 11 1c 2c 09 2b 00 11 1c 17 2e 08 2b 0c 11 13 13 13 2b 06 11 13 13 13 2b 00 00 11 1b 17 58 13 1b 11 1b 18 fe 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_31
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 09 2c 5b 00 02 7b ?? 00 00 04 08 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 11 04 2c 22 00 02 7b ?? 00 00 04 08 6f ?? 00 00 0a 16}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 0c 2b 33 12 02 28 ?? 00 00 0a 0d 00 02 7b ?? 00 00 04 6f ?? 00 00 0a 09 6f ?? 00 00 0a 73 ?? 00 00 0a 25 09 6f ?? 00 00 0a 6f ?? 00 00 0a 00 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_32
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 06 2b 68 16 13 07 2b 53 07 11 06 11 07 6f ?? 00 00 0a 13 08 08 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 20 00 b8 00 00 2f 0d 08 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 20 00 b8 00 00 2f 0d 08 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 11 07 17 58 13 07 11 07 07}  //weight: 2, accuracy: Low
        $x_1_2 = "Whisper.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_33
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0b 1f 0a 13 0b 2b 86 00 02 06 07 6f ?? 00 00 0a 0c 03 6f ?? 00 00 0a 19 58 04 fe 02 16 fe 01 0d 18 13 0b}  //weight: 2, accuracy: Low
        $x_2_2 = {01 25 16 03 16 9a a2 25 17 03 17 9a a2 25 18 04 a2 0a 09 1f 0b 93}  //weight: 2, accuracy: High
        $x_1_3 = "AppSistemaGaragem.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_34
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 16 13 04 2b 68 16 13 05 2b 53 07 11 04 11 05 6f ?? 00 00 0a 13 06 08 12 06 28 ?? 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 20 00 40 01 00 2f 0d 08 12 06 28 ?? 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 20 00 40 01 00 2f 0d 08 12 06 28}  //weight: 2, accuracy: Low
        $x_1_2 = "VP_Lab2_final.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_35
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "WordProcessorChamberlin 1994" wide //weight: 2
        $x_2_2 = "Andrewsy Lib" wide //weight: 2
        $x_2_3 = "62600c6c-2b3c-4bdb-8847-89ba729d5974" ascii //weight: 2
        $x_1_4 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_5 = "GetManifestResourceStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_36
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {25 16 16 02 08 91 28 ?? 00 00 0a 25 17 16 02 08 17 58 91 28 ?? 00 00 0a 0d 06 09 28 ?? 00 00 06 13 04 07 08 11 04 16 16 28 ?? 00 00 0a d2 9c 07 08 17 58 11 04 17 16 28}  //weight: 2, accuracy: Low
        $x_1_2 = "investdirectinsurance.com/assuence/litesolidCha/Chief.he" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFB_2147832252_37
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFB!MTB"
        threat_id = "2147832252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "RoyNES Nexus" wide //weight: 6
        $x_5_2 = "Nebula Horizon Technologies" wide //weight: 5
        $x_4_3 = "Quantum.2025.Spring" wide //weight: 4
        $x_3_4 = "Take Screenshot" wide //weight: 3
        $x_2_5 = "listenning on port" wide //weight: 2
        $x_1_6 = "client stopped without closing properly" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AJBI_2147832254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AJBI!MTB"
        threat_id = "2147832254"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {70 18 8d 17 00 00 01 25 16 72 ?? ?? ?? 70 a2 25 17 72 ?? ?? ?? 70 a2 14 14 14 28}  //weight: 2, accuracy: Low
        $x_1_2 = "Religion_Jeopardy" wide //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABNN_2147832525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABNN!MTB"
        threat_id = "2147832525"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 8e 69 5d 91 02 07 91 61 d2 6f ?? ?? ?? 0a 07 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ANP_2147832618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ANP!MTB"
        threat_id = "2147832618"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 09 11 04 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 07 06 28 ?? ?? ?? 06 d2 9c 00 11 04 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "MatchingPairsGame" wide //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ATN_2147832744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ATN!MTB"
        threat_id = "2147832744"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 7e ?? ?? ?? 04 06 28 ?? ?? ?? 06 d2 9c 00 09 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "GetPixel" ascii //weight: 1
        $x_1_3 = "HealthStopClient" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFO_2147832747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFO!MTB"
        threat_id = "2147832747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 0a 2b 1b 02 06 02 06 91 7e 06 00 00 04 06 7e 06 00 00 04 8e 69 5d 91 61 d2 9c 06 17 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFO_2147832747_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFO!MTB"
        threat_id = "2147832747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0d 16 13 0a 2b 11 00 09 11 0a 08 11 0a 94 d2 9c 00 11 0a 17 58 13 0a 11 0a 08 8e 69 fe 04 13 0b 11 0b 2d e2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFO_2147832747_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFO!MTB"
        threat_id = "2147832747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 16 0d 2b 1a 07 09 06 09 91 08 09 08 6f ?? 01 00 0a 5d 6f ?? 01 00 0a 61 d2 9c 09 17 58 0d 09 06 8e 69 32 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFO_2147832747_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFO!MTB"
        threat_id = "2147832747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 2a 2b 2f 16 2d f2 2b 31 72 ?? ?? ?? 70 2b 2d 16 2c 31 26 26 2b 34 2b 35 06 16 06 8e 69 6f ?? 00 00 0a 0c 1c 2c d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFO_2147832747_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFO!MTB"
        threat_id = "2147832747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 59 9a 0c 08 28 ?? 00 00 0a 16 fe 01 13 06 11 06 2d 03 00 2b 2f 00 06 09 6f ?? 00 00 0a 08 6f ?? 00 00 0a 00 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFO_2147832747_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFO!MTB"
        threat_id = "2147832747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 16 0d 2b 22 07 09 18 6f 1e 00 00 0a 1f 10 28 b3 00 00 0a 13 04 11 04 16 32 08 08 11 04 6f 3c 00 00 0a 09 18 58 0d 09 07 6f 21 00 00 0a 32 d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFO_2147832747_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFO!MTB"
        threat_id = "2147832747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {19 5d 13 17 17 11 16 58 19 5d 13 18 18 11 16 58 19 5d 13 19 19 8d ?? 00 00 01 13 1a 11 1a 16 12 14 28 ?? 00 00 0a 9c 11 1a 17 12 14 28 ?? 00 00 0a 9c 11 1a 18 12 14 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFO_2147832747_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFO!MTB"
        threat_id = "2147832747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 09 2b 19 00 06 7b ?? 01 00 04 11 24 11 09 91 6f ?? 01 00 0a 00 00 11 09 17 58 13 09 11 09 11 16 fe 04 13 25}  //weight: 2, accuracy: Low
        $x_1_2 = "DoAnCaNhan" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFO_2147832747_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFO!MTB"
        threat_id = "2147832747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 16 91 13 05 08 17 8d ?? ?? ?? 01 25 16 11 05 9c 6f ?? ?? ?? 0a 09 18 58 0d 09 07 6f ?? ?? ?? 0a fe 04 13 06 11 06 2d c4}  //weight: 2, accuracy: Low
        $x_1_2 = "QuanLyBanHang" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFO_2147832747_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFO!MTB"
        threat_id = "2147832747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 11 04 09 8e 69 5d 09 8e 69 58 09 8e 69 5d 91 13 05 11 04 17 58 08 5d 08 58 08 5d 13 06 07 11 06 08 5d 08 58 08 5d 91 13 07 07 11 04 08 5d 08 58 08 5d 91 11 05 61 11 07 59 20 00 02 00 00 58 20 00 01 00 00 5d 20 00 04 00 00 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFO_2147832747_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFO!MTB"
        threat_id = "2147832747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0d 2b 31 00 07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06}  //weight: 2, accuracy: Low
        $x_1_2 = "NetworkArithmeticGame" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFO_2147832747_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFO!MTB"
        threat_id = "2147832747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {17 58 08 5d 13 0d 02 07 11 0a 91 11 0c 61 07 11 0d 91 59 28 ?? ?? ?? 06 13 0e 07 11 0a 11 0e 28 ?? ?? ?? 0a d2 9c 00 11 0a 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "detectVideoApp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFO_2147832747_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFO!MTB"
        threat_id = "2147832747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 8e 69 5d 91 13 07 08 11 05 1f 16 5d 91 13 08 07 11 05 07 11 05 91 11 08 61 11 07 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 00 11 05 17 58}  //weight: 2, accuracy: High
        $x_1_2 = "Distribuidora" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFO_2147832747_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFO!MTB"
        threat_id = "2147832747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0a 2b 0e 02 03 06 04 05 28 ?? 00 00 06 06 17 58 0a 06 02 6f ?? 00 00 0a 2f 0b 04 6f ?? 00 00 0a 05 fe 04 2b 01 16 0b 07 2d d9}  //weight: 2, accuracy: Low
        $x_1_2 = {02 03 04 6f ?? 00 00 0a 0a 0e 04 05 6f ?? 00 00 0a 59 0b 06 07 05 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFO_2147832747_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFO!MTB"
        threat_id = "2147832747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 0d 2b 3f 00 09 02 7b ?? 00 00 04 8e 69 17 59 fe 02 13 04 11 04 2c 04 16 0c 2b 3a 02 7b ?? 00 00 04 09 91 20 80 00 00 00 5f 20 80 00 00 00 fe 01 16 fe 01 13 05 11 05 2c 04 09 0c 2b 18 00 09 17 58 0d 09 06 fe 02 16 fe 01 13 06 11 06 2d b4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFO_2147832747_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFO!MTB"
        threat_id = "2147832747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 0a 2b 19 00 02 06 94 07 fe 02 0c 08 2c 09 00 02 06 94 0b 03 06 54 00 00 06 17 58 0a 06 02 8e 69 fe 04 0d 09 2d}  //weight: 2, accuracy: High
        $x_1_2 = "Paleolithic Cooperation" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFO_2147832747_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFO!MTB"
        threat_id = "2147832747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 13 04 16 13 05 2b 19 11 04 11 05 a3 ?? 00 00 01 13 06 09 11 06 6f ?? 00 00 0a 11 05 17 58 13 05 11 05 11 04 8e 69 32 df}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 16 0b 38 ?? 00 00 00 06 07 17 5b 7e ?? 00 00 0a a4 ?? 00 00 01 07 17 58 0b 07 02 8e 69 32 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFO_2147832747_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFO!MTB"
        threat_id = "2147832747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 16 0c 2b 14 07 08 02 7b ?? ?? ?? 04 08 91 28 ?? ?? ?? 0a 9d 08 17 58 0c 08 06 fe 04 0d 09 2d e4}  //weight: 1, accuracy: Low
        $x_1_2 = {26 2b 1c 00 02 7b ?? 00 00 04 07 6f ?? 00 00 0a 6f ?? 00 00 06 26 1f 64 28 ?? 00 00 0a 00 00 07 6f ?? 00 00 0a 16 fe 01 0c 08 2d d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFO_2147832747_18
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFO!MTB"
        threat_id = "2147832747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 04 2b 4e 00 08 11 04 08 8e 69 5d 02 08 11 04 08 8e 69 5d 91 09 11 04 09 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 28 ?? 00 00 0a 08 11 04 17 58 08 8e 69 5d 91}  //weight: 2, accuracy: Low
        $x_1_2 = "SwitchboardServer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFO_2147832747_19
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFO!MTB"
        threat_id = "2147832747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 19 32 50 12 00 28 ?? 00 00 0a 1f 10 62 12 00 28 ?? 00 00 0a 1e 62 60 12 00 28 ?? 00 00 0a 60 0c 03 19 8d ?? 00 00 01 25 16 08 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 08 1e}  //weight: 1, accuracy: Low
        $x_2_2 = {16 0a 2b 28 16 0b 2b 0e 02 03 06 07 04 28 ?? 00 00 06 07 17 58 0b 07 02 28 ?? 00 00 06 2f 09 03 6f ?? 00 00 0a 04 32 e0 06 17 58}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFO_2147832747_20
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFO!MTB"
        threat_id = "2147832747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LAY_DON_GIA_THEO_MA_HH" ascii //weight: 1
        $x_1_2 = "LAY_SO_LUONG_TON_THEO_MA_HH" ascii //weight: 1
        $x_1_3 = "Frm_HH_CHI_TIET" ascii //weight: 1
        $x_1_4 = "QUAN_System.Frm" ascii //weight: 1
        $x_1_5 = "dc9d373f-dfaa-432f-98ec-965682f2d65f" ascii //weight: 1
        $x_1_6 = "2016 by ManMan89" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFO_2147832747_21
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFO!MTB"
        threat_id = "2147832747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 0e 00 11 04 09 16 11 05 6f ?? 00 00 0a 00 00 08 09 16 09 8e 69 6f ?? 01 00 0a 25 13 05 16 fe 02 13 08 11 08 2d db}  //weight: 2, accuracy: Low
        $x_1_2 = "e619b80b-ba89-4324-87bf-2f516fe328d3" ascii //weight: 1
        $x_1_3 = "2023CryptsDone\\EduPlus\\obj\\Debug\\Elnabfva.pdb" ascii //weight: 1
        $x_1_4 = "http://kothariqhyto.com/1966" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AUB_2147832876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AUB!MTB"
        threat_id = "2147832876"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 7e ?? ?? ?? 04 06 28 ?? ?? ?? 06 d2 9c 00 09 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "EchoClient" wide //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ADQ_2147832880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ADQ!MTB"
        threat_id = "2147832880"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0b 16 0c 2b 49 00 16 0d 2b 31 00 07 08 09 28}  //weight: 2, accuracy: High
        $x_1_2 = "DCPUVM" wide //weight: 1
        $x_1_3 = "UYR0010453" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ALD_2147833486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ALD!MTB"
        threat_id = "2147833486"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 7e ?? ?? ?? 04 06 28 ?? ?? ?? 06 d2 9c 00 09 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "Savas.Desktop" wide //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ADI_2147833487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ADI!MTB"
        threat_id = "2147833487"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 0b 16 0c 2b 49 00 16 0d 2b 31 00 07 08 09 28}  //weight: 2, accuracy: High
        $x_1_2 = "Pink" wide //weight: 1
        $x_1_3 = "D52847352345" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AHC_2147833488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AHC!MTB"
        threat_id = "2147833488"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 0b 16 0c 2b ?? ?? ?? 0d 2b 31 00 07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 7e ?? ?? ?? 04 06 28 ?? ?? ?? 06 d2 9c 00 09 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "Ski" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ANSC_2147833490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ANSC!MTB"
        threat_id = "2147833490"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 44 2b 45 18 5b 2b 44 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 08 18 25 2c b5 58 0c 1d 2c 04 08 06 32 db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AIEZ_2147833784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AIEZ!MTB"
        threat_id = "2147833784"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 04 2b 35 00 08 09 11 04 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 07 06 28 ?? ?? ?? 06 d2 6f ?? ?? ?? 0a 00 00 11 04 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "NetSyncObserver" wide //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
        $x_1_4 = "Hyves" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AEDW_2147833825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AEDW!MTB"
        threat_id = "2147833825"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 09 11 04 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 07 17 8d ?? ?? ?? 01 25 16 28 ?? ?? ?? 06 d2 9c 6f ?? ?? ?? 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 05 11 05 2d b8}  //weight: 2, accuracy: Low
        $x_1_2 = "boat" wide //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AEDS_2147833826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AEDS!MTB"
        threat_id = "2147833826"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 16 0d 2b 57 00 16 13 04 2b 3d 00 08 09 11 04 28 ?? ?? ?? 06 28 ?? ?? ?? 06}  //weight: 2, accuracy: Low
        $x_1_2 = "Sup" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AEDJ_2147833827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AEDJ!MTB"
        threat_id = "2147833827"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ToArray" ascii //weight: 1
        $x_1_2 = "GetPixel" ascii //weight: 1
        $x_1_3 = "GamestatsBase" wide //weight: 1
        $x_1_4 = "AXXVCSVF" ascii //weight: 1
        $x_2_5 = "boat" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AIFC_2147833829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AIFC!MTB"
        threat_id = "2147833829"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 09 11 04 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 07 06 28 ?? ?? ?? 06 d2 6f ?? ?? ?? 0a 00 00 11 04 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "Hyves" wide //weight: 1
        $x_1_3 = "CheatMenu" wide //weight: 1
        $x_1_4 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ACKD_2147833958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ACKD!MTB"
        threat_id = "2147833958"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 8e 69 5d 93 7e ?? ?? ?? 04 07 91 61 d2 9c 00 07 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "Trump_and_joe_biden_png" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AGXQ_2147834283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AGXQ!MTB"
        threat_id = "2147834283"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0d 2b 36 00 07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 17 13 04 00 28 ?? ?? ?? 06 d2 06 28 ?? ?? ?? 06 00 00 00 09 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "Malaga_game" wide //weight: 1
        $x_1_3 = "intel22" wide //weight: 1
        $x_1_4 = "GetPixel" ascii //weight: 1
        $x_1_5 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AIGE_2147834288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AIGE!MTB"
        threat_id = "2147834288"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? ?? ?? 0a 02 07 17 58 02 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? ?? ?? 0a 9c 00 07 15 58}  //weight: 2, accuracy: Low
        $x_1_2 = "BananaHook" wide //weight: 1
        $x_1_3 = "G4D54C7D48A57E47Y87HB4" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ADJN_2147834663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ADJN!MTB"
        threat_id = "2147834663"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 d2 06 28 ?? ?? ?? 06 00 00 09 1b 59}  //weight: 2, accuracy: Low
        $x_1_2 = "CDown" wide //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
        $x_1_4 = "Zabawki" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AGYX_2147834664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AGYX!MTB"
        threat_id = "2147834664"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? ?? ?? 0a 02 07 17 58 02 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 07 15 58}  //weight: 2, accuracy: Low
        $x_1_2 = "EcoBoost" wide //weight: 1
        $x_1_3 = "745445BJ5CHO8980FGGAZ7" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFM_2147834667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFM!MTB"
        threat_id = "2147834667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 0a 17 58 08 5d 13 0d 02 07 11 0a 91 11 0c 61 07 11 0d 91 59 28 ?? 00 00 06 13 0e 11 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFM_2147834667_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFM!MTB"
        threat_id = "2147834667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 8e 69 5d 91 13 06 08 11 05 1f 16 5d 91 13 07 07 11 05 07 11 05 91 11 07 61 11 06 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 00 11 05 17 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFM_2147834667_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFM!MTB"
        threat_id = "2147834667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 13 0d 2b 29 11 34 11 0d 1d 5f 91 13 1f 11 1f 19 62 11 1f 1b 63 60 d2 13 1f 11 05 11 0d 11 05 11 0d 91 11 1f 61 d2 9c 11 0d 17 58 13 0d 11 0d 11 08 32 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFM_2147834667_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFM!MTB"
        threat_id = "2147834667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 05 2b 21 00 02 7b ?? 00 00 04 11 05 02 7b ?? 00 00 04 11 05 91 20 e5 05 00 00 59 d2 9c 00 11 05 17 58 13 05 11 05 02 7b ?? 00 00 04 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFM_2147834667_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFM!MTB"
        threat_id = "2147834667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 06 07 6f ?? 00 00 0a 0c 04 03 6f ?? 00 00 0a 59 0d 09 19 32 2c 03 19 8d 58 00 00 01 25 16 12 02 28 ?? 00 00 0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 02 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFM_2147834667_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFM!MTB"
        threat_id = "2147834667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0d 2b 1d 07 09 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 13 05 08 11 05 6f ?? ?? ?? 0a 09 18 58 0d 09 07 6f ?? ?? ?? 0a fe 04 13 06 11 06 2d d4}  //weight: 2, accuracy: Low
        $x_1_2 = "QuanLyBanHang" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFM_2147834667_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFM!MTB"
        threat_id = "2147834667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 0a 06 6f 7e 00 00 0a 03 73 7f 00 00 0a 0b de 14 0c 08 6f 73 00 00 0a 73 5f 00 00 06 73 80 00 00 0a 0b de}  //weight: 1, accuracy: High
        $x_1_2 = {0a 07 03 6f 9b 00 00 06 07 06 6f 6c 00 00 0a 6f 9d 00 00 06 07 06 6f 79 00 00 0a 6f a3 00 00 06 07 06 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFM_2147834667_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFM!MTB"
        threat_id = "2147834667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 05 17 8d 08 00 00 01 25 16 7e 4b 00 00 04 a2 13 06 72 f2 16 00 70 72 bf 18 00 70 72 01 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 13 07 11 07 09 11 05 14 14 11 06}  //weight: 2, accuracy: Low
        $x_1_2 = "Avtopark.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFM_2147834667_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFM!MTB"
        threat_id = "2147834667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 9a 0c 08 19 8d ?? ?? ?? 01 25 16 7e 2b 00 00 04 16 9a a2 25 17 7e 2b 00 00 04 17 9a a2 25 18}  //weight: 2, accuracy: Low
        $x_2_2 = {16 0b 2b 1a 00 06 07 02 07 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 00 07 17 58 0b 07 06 8e 69}  //weight: 2, accuracy: Low
        $x_1_3 = "AS1AChowdhury" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFM_2147834667_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFM!MTB"
        threat_id = "2147834667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0b 2b 30 02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? 00 00 0a 59 0d 03 08 09 28 ?? 00 00 06 03 08 09 28 ?? 00 00 06 03 6f ?? 00 00 0a 04 32 01 2a 07 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "EP2_Filosofos" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFM_2147834667_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFM!MTB"
        threat_id = "2147834667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 09 18 62 11 04 17 63 59 61 0c 08 11 04 5f 09 1f 3f 61 60 0d 09 1a 5d 2c 06 11 04 19 59 2b 04 11 04 18 58 13 04 00 11 0c 17 58 13 0c 11 0c 1f 4b fe 04 13 0d 11 0d 2d c6}  //weight: 2, accuracy: High
        $x_1_2 = "PersonnelTracking" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFM_2147834667_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFM!MTB"
        threat_id = "2147834667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 d2 06 28 ?? ?? ?? 06 00 00 09 1b 59 1c 58}  //weight: 2, accuracy: Low
        $x_1_2 = "GetPixel" ascii //weight: 1
        $x_1_3 = "CDown" wide //weight: 1
        $x_1_4 = "ResumePortrait" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFM_2147834667_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFM!MTB"
        threat_id = "2147834667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {25 16 1f 3d 9d 6f ?? 00 00 0a 0c 08 16 9a 6f ?? 00 00 0a 13 06 11 06 72 ?? 09 00 70 28 ?? 00 00 0a 2d 02 2b 21 08 17 9a 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "myTaskScheduler\\obj\\Debug\\myTaskScheduler.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFM_2147834667_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFM!MTB"
        threat_id = "2147834667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 08 11 05 58 91 03 11 05 07 5d 91 61 d2 9c 00 11 05 17 58 13 05 11 05 09 fe 04 13 06 11 06 2d da}  //weight: 2, accuracy: High
        $x_2_2 = "ainvestinternational.com" wide //weight: 2
        $x_1_3 = "UBOTexture" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFM_2147834667_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFM!MTB"
        threat_id = "2147834667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "59157c3f-1dae-42dc-8c2f-9eb0fca760fd" ascii //weight: 1
        $x_1_2 = "InventoryMaintenance.Properties.Resources" wide //weight: 1
        $x_1_3 = "InventoryMaintenance.Resource1" wide //weight: 1
        $x_1_4 = "Are you sure you want to delete" wide //weight: 1
        $x_1_5 = "Confirm Delete" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFM_2147834667_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFM!MTB"
        threat_id = "2147834667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ReichUI.Properties.Resources" wide //weight: 2
        $x_1_2 = "Failed to retrieve custom cursor from embedded resource" wide //weight: 1
        $x_1_3 = "77cd30fd-bf09-4843-8e1b-14960d283e0a" ascii //weight: 1
        $x_1_4 = "get_ResourceManager" ascii //weight: 1
        $x_1_5 = "GetManifestResourceNames" ascii //weight: 1
        $x_1_6 = "CreateIconFromResource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFM_2147834667_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFM!MTB"
        threat_id = "2147834667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FoLock v2 Beta" wide //weight: 1
        $x_1_2 = "Sign Up for FoLock" wide //weight: 1
        $x_1_3 = "SaaN\\Sahan\\Saan All\\Sahan\\Sahan\\My Projects\\FoLock V2\\FoLock V2.accdb" wide //weight: 1
        $x_1_4 = "JAM is an application software designed for personal folder security" wide //weight: 1
        $x_1_5 = "The REAVIS Project" wide //weight: 1
        $x_1_6 = "JAM Folder Protector" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ANZI_2147835044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ANZI!MTB"
        threat_id = "2147835044"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 13 04 07 6f ?? ?? ?? 0a 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 13 05 de 14}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AHAH_2147835046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AHAH!MTB"
        threat_id = "2147835046"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 d2 06 28 ?? ?? ?? 06 00 00 09 1b 59 1c 58 0d 09 17 fe 04 13 09 11 09 2d c3 06 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "GetPixel" ascii //weight: 1
        $x_1_3 = "Aeeee" wide //weight: 1
        $x_1_4 = "WillisRubicsCube" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AHAT_2147835048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AHAT!MTB"
        threat_id = "2147835048"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? ?? ?? 0a 6e 02 07 17 58 02 8e 69 5d 91 28 ?? ?? ?? 0a 6a 59 20}  //weight: 2, accuracy: Low
        $x_1_2 = "Electro" wide //weight: 1
        $x_1_3 = "SimFarm" wide //weight: 1
        $x_1_4 = "D774Z478V4S7392GGBH54G" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AHAN_2147835193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AHAN!MTB"
        threat_id = "2147835193"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 11 05 11 04 6f ?? ?? ?? 0a 13 06 20 ff 00 00 00 20 ff 00 00 00 12 06 28 ?? ?? ?? 0a 59 20 ff 00 00 00 12 06}  //weight: 2, accuracy: Low
        $x_1_2 = "Softweyr.Configuration" wide //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AAFM_2147835194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AAFM!MTB"
        threat_id = "2147835194"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? ?? ?? 0a 6e 02 07 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "OIY54Y55ZBEQ44GF4F57N5" wide //weight: 1
        $x_1_3 = "Luis1" wide //weight: 1
        $x_1_4 = "Kolaito" ascii //weight: 1
        $x_1_5 = "WaraUi" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AZBF_2147835196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AZBF!MTB"
        threat_id = "2147835196"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 00 08 01 00 8d 5f 00 00 01 0a 16 0b 2b 1a 00 06 07 02 07 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 00 07 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "FinalProject" wide //weight: 1
        $x_1_3 = "murey" ascii //weight: 1
        $x_1_4 = "Humphrey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AGCF_2147835373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AGCF!MTB"
        threat_id = "2147835373"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 06 2b 15 07 11 06 06 11 06 9a 1f 10 28 ?? ?? ?? 0a 9c 11 06 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "Impacta.Alunos.UI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 03 02 03 91 1d 59 1f 09 59 d2 25 0a 9c 06 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 2b 0d 00 06 28 ?? ?? ?? 06 00 00 06 17 58 0a 06 7e 08 00 00 04 8e 69 fe 04 0b 07 2d e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 16 0b 2b 1c 02 06 03 16 16 28 07 00 00 06 16 31 01 2a 20 e9 04 00 00 28 0d 00 00 0a 07 17 58 0b 07 1a 32 e0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 13 39 2b 2c 11 04 11 39 11 04 11 39 91 09 11 37 91 11 39 1a 5d 1d 5f 62 d2 61 11 04 11 39 17 da 91 61 20 00 01 00 00 5d b4 9c 11 39 17 d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {26 2b 28 0a 2b f1 0b 2b f8 02 50 06 91 19 2d 18 26 02 50 06 02 50 07 91 9c 02 50 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e6 06 07 32 da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {95 11 0f 11 13 95 58 20 ff 00 00 00 5f 13 2f 11 10 13 30 07 11 30 91 13 31 11 0f 11 2f 95 13 32 11 31 11 32 61 13 33 11 0e 11 30 11 33 d2 9c 11 10 17 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 5a 58 11 11 07 6f ?? 00 00 0a 5a 58 13 0a 11 0c 11 05 11 0a 91 58 13 0c 11 0d 11 05 11 0a 17 58 91 58 13 0d 11 0e 11 05 11 0a 18 58 91 58}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 11 12 0f 28 ?? 00 00 0a 13 12 12 0f 28 ?? 00 00 0a 13 13 12 0f 28 ?? 00 00 0a 13 14 11 0d 16 5f 13 15 11 15 19 5d 13 16 17 11 15 58 19}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 11 07 07 11 07 9a 1f 10 28 ?? ?? ?? 0a 9c 11 07 17 58 13 07}  //weight: 2, accuracy: Low
        $x_1_2 = "MainStoreFunctionality.Models" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 8e 69 6a 5d d4 07 11 07 07 8e 69 6a 5d d4 91 08 11 07 08 8e 69 6a 5d d4 91 61 28 ?? 00 00 06 d2 07 11 07 17 6a 58 07 8e 69 6a 5d d4 91 28 ?? 00 00 06 d2 59 20 00 01 00 00 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0a 06 72 61 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 ?? 30 00 00 0a 28 ?? 00 00 06 0b 07 16 07 8e 69 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 8e 69 5d 09 8e 69 58 13 10 11 10 09 8e 69 5d 13 11 09 11 11 91 13 12 11 0f 17 58 08 5d 13 13 11 13 08 58 13 14 11 14 08 5d 13 15 11 15 08 5d 08 58}  //weight: 2, accuracy: High
        $x_1_2 = "KellermanSoftware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0a 2b 10 00 02 06 03 04 28 ?? 00 00 06 00 00 06 17 58 0a 06 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 0b 07 2d d7}  //weight: 2, accuracy: Low
        $x_1_2 = "BuaLagbe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0b 2b 3e 00 02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? 01 00 0a 59 0d 03 08 09 28 ?? 00 00 06 00 03 08 09 28 ?? 00 00 06 00 03 6f ?? 01 00 0a 04 fe 04 16 fe 01 13 04 11 04 2c 02 2b 28 00 07 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 13 0f 2b 5a 00 11 07 17 58 20 ff 00 00 00 5f 13 07 11 05 11 04 11 07 95 58 20 ff 00 00 00 5f 13 05 11 04 11 07 95 13 06 11 04 11 07 11 04 11 05 95 9e 11 04 11 05 11 06 9e 09 11 0f 07 11 0f 91 11 04 11 04 11 07 95 11 04 11 05 95 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 13 04 16 13 05 2b 3c 11 04 11 05 9a 0c 08 6f ?? 00 00 0a 04 28 ?? 00 00 0a 2c 22 72 ?? 00 00 70 08 72 ?? 00 00 70 18 8d ?? 00 00 01 13 06 11 06 16 03 a2 11 06 28 ?? 00 00 06 0d de 10 11 05 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 0c 2b 60 16 0d 2b 4f 07 08 09 6f 55 00 00 0a 13 09 06 12 09 28 56 00 00 0a 6f 57 00 00 0a 06 6f 58 00 00 0a 20 00 b8 00 00 2f 0d 06 12 09 28 59 00 00 0a 6f 57 00 00 0a 06 6f 58 00 00 0a 20 00 b8 00 00 2f 0d 06 12 09 28 5a 00 00 0a 6f 57 00 00 0a 09 17 58 0d 09 07 6f 5b 00 00 0a 32 a8 08 17 58 0c 08 07 6f 5c 00 00 0a 32 97 07 6f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {58 11 15 11 15 8e 69 12 00 28 ?? 00 00 06 2d 02 16 2a 11 0d 1f 28 58 13 0d 11 11 17 58 68 13 11 11 11 04 07 1c 58}  //weight: 3, accuracy: Low
        $x_2_2 = {04 11 0d 1f 0c 58 28 ?? 00 00 0a 13 12 04 11 0d 1f 10 58 28 ?? 00 00 0a 13 13 04 11 0d 1f 14 58 28 ?? 00 00 0a 13 14 11 13 2c 33 11 13 8d ?? 00 00 01 13 15 04 11 14 11 15 16 11 13}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_18
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7dbedace-6382-4ac0-a787-0f578cf0ec04" ascii //weight: 1
        $x_1_2 = "Database Image Add-2WAYS" wide //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "get_ResourceManager" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_19
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 09 11 0a 9a 13 0b 00 06 02 11 0b 6f 1f 00 00 0a 28 04 00 00 06 58 0a 00 11 0a 17 58 13 0a 11 0a 11 09 8e 69 32 d9}  //weight: 2, accuracy: High
        $x_1_2 = "816fc041-3159-4204-a9e6-f6c048d61b10" ascii //weight: 1
        $x_1_3 = "Mergin.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_20
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 06 2b 2e 11 05 11 06 9a 13 07 00 11 04 6f ?? 01 00 0a 11 07 28 ?? 00 00 0a 13 08 11 08 2c 0b 00 06 07 11 04 a2 07 17 58}  //weight: 1, accuracy: Low
        $x_1_2 = {0d 2b 48 00 06 09 06 8e 69 5d 06 09 06 8e 69 5d 91 07 09 07 6f ?? 01 00 0a 5d 6f ?? 02 00 0a 61 28 ?? 00 00 0a 06 09 17 58 06 8e 69 5d 91 28 ?? 02 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? 02 00 0a 9c 00 09 15 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_21
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "p-Project-p\\obj\\x86\\Debug\\MiNlIl.pdb" ascii //weight: 1
        $x_2_2 = "kothariqhyto.com" wide //weight: 2
        $x_1_3 = "496ba77c-9843-4ca4-ac0d-35250fbac1e9" ascii //weight: 1
        $x_1_4 = "MiNlIl.logon.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_22
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 16 ac 01 00 13 04 2b 19 00 06 11 04 06 8e 69 5d 02 06 11 04 28 ?? ?? ?? 06 9c 00 11 04 15 58 13 04 11 04 16 fe 04 16 fe 01 13 05 11 05 2d d9}  //weight: 2, accuracy: Low
        $x_1_2 = "UncleNabeelsBakery" wide //weight: 1
        $x_1_3 = "System.Reflection.Assembly" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_23
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 0a 11 09 6f ?? ?? ?? 0a 13 0b 16 13 0c 11 05 11 08 9a 72 55 04 00 70 28 ?? ?? ?? 0a 13 0d 11 0d 2c 0d 00 12 0b 28 ?? ?? ?? 0a 13 0c 00 2b 42 11 05 11 08 9a 72 59 04 00 70 28 ?? ?? ?? 0a 13 0e 11 0e 2c 0d 00 12 0b 28 ?? ?? ?? 0a 13 0c 00 2b 20 11 05 11 08 9a 72 5d 04 00 70 28 ?? ?? ?? 0a 13 0f 11 0f 2c 0b 00 12 0b 28 ?? ?? ?? 0a 13 0c 00 07 11 0c}  //weight: 2, accuracy: Low
        $x_1_2 = "CSDL_QLNS_QLLUONG" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFK_2147835374_24
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFK!MTB"
        threat_id = "2147835374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {02 03 07 04 05 28 ?? 00 00 06 00 73 7f 00 00 0a 13 05 11 05 72 a7 08 00 70 6f ?? 00 00 0a 26 11 05 72 a7 08 00 70 6f ?? 00 00 0a 26 07 17 58 0b 00 07 02 6f}  //weight: 4, accuracy: Low
        $x_3_2 = "rdoBtnSoftDrinks" wide //weight: 3
        $x_2_3 = "rdoBtnAlcohol" wide //weight: 2
        $x_1_4 = "Unfortunately You have entered the wrong password three times" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AGCG_2147835375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AGCG!MTB"
        threat_id = "2147835375"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0a 2b 11 08 06 07 06 9a 1f 10 28 ?? ?? ?? 0a 9c 06 17 58}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AGCIC_2147835502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AGCIC!MTB"
        threat_id = "2147835502"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 07 2b 15 08 11 07 07 11 07 9a 1f 10 28 ?? ?? ?? 0a 9c 11 07 17 58 13 07}  //weight: 2, accuracy: Low
        $x_1_2 = "MagicUI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AMF_2147835506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AMF!MTB"
        threat_id = "2147835506"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 16 0b 2b 13 00 06 07 06 07 91 20 b5 03 00 00 59 d2 9c 07 17 58 0b 00 07 06 8e 69 fe 04 0d}  //weight: 2, accuracy: High
        $x_1_2 = "Game-of-Life" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AMF_2147835506_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AMF!MTB"
        threat_id = "2147835506"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0c 2b 46 16 0d 2b 3a 16 13 04 2b 2c 11 07 07 09 58 08 11 04 58 6f ?? ?? ?? 0a 13 0b 12 0b 28 ?? ?? ?? 0a 13 09 11 06 11 05 11 09 9c 11 05 17 58 13 05 11 04 17 58 13 04 11 04 17 32 cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AMF_2147835506_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AMF!MTB"
        threat_id = "2147835506"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 07 11 0c 11 06 11 0c 9a 1f 10 28 ?? ?? ?? 0a 9c 11 0c 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "MainPlayerManagementForm" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AMF_2147835506_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AMF!MTB"
        threat_id = "2147835506"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5d 91 13 07 11 06 17 58 08 5d 13 08 07 11 06 91 11 07 61 13 09 07 11 08 91 13 0a 02 11 09 11 0a 28 ?? 00 00 06 13 0b 07 11 06 11 0b 28 ?? 00 00 0a 9c 00 11 06 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "EmuLister" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AMF_2147835506_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AMF!MTB"
        threat_id = "2147835506"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5d 91 0d 07 08 91 09 61 07 08 17 58 07 8e 69 5d 91 13 04 11 04 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 05 07 08 11 05 28 ?? 00 00 0a 9c 08 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "EmployeeInfoApp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AMF_2147835506_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AMF!MTB"
        threat_id = "2147835506"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {25 16 09 a2 25 17 19 8d ?? 00 00 01 25 16 02 7b ?? 00 00 04 a2 25 17 02 7b ?? 00 00 04 a2 25 18}  //weight: 2, accuracy: Low
        $x_2_2 = {16 0c 2b 1a 00 07 08 18 5b 02 08 18 6f 6f 00 00 0a 1f 10 28 70 00 00 0a 9c 00 08 18 58 0c 08 06 fe 04 0d 09 2d de}  //weight: 2, accuracy: High
        $x_1_3 = "Search_Indexer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AMF_2147835506_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AMF!MTB"
        threat_id = "2147835506"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 2c 08 11 04 6f ?? ?? ?? 0a 00 dc 28 ?? ?? ?? 06 02 16 03 8e 69 6f ?? ?? ?? 0a 0b 07 28 ?? ?? ?? 0a 0c 08 6f ?? ?? ?? 0a 0d 09 16 9a 13 06 de 0b 06 2c 07 06}  //weight: 2, accuracy: Low
        $x_1_2 = "MotorSimulation\\MotorSimulation\\ExampleFile.txt" wide //weight: 1
        $x_1_3 = "Login Successful" wide //weight: 1
        $x_1_4 = "Motor.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFL_2147835608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFL!MTB"
        threat_id = "2147835608"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 11 07 07 11 07 9a 1f 10 28 ?? ?? ?? 0a 9c 11 07 17 58 13 07}  //weight: 2, accuracy: Low
        $x_1_2 = "ShareCreation" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AHDN_2147835611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AHDN!MTB"
        threat_id = "2147835611"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 11 07 06 11 07 9a 1f 10 28 ?? ?? ?? 0a 9c 11 07 17 58 13 07}  //weight: 2, accuracy: Low
        $x_1_2 = "Runo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AILF_2147835705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AILF!MTB"
        threat_id = "2147835705"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 08 2b 18 07 06 11 08 9a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 11 08 17 58 13 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AGCP_2147835870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AGCP!MTB"
        threat_id = "2147835870"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 06 1c 8d 17 00 00 01 25 16 72 67 00 00 70 a2 25 17 72 6d 00 00 70 a2 25 18 72 73 00 00 70 a2 25 19}  //weight: 2, accuracy: High
        $x_1_2 = "Stupid" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABDO_2147835893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABDO!MTB"
        threat_id = "2147835893"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {13 05 18 2c f6 18 2c 2b 07 08 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 06 11 06 11 05 16 11 05 8e 69 6f ?? ?? ?? 0a de 0c 11 06 2c 07 11 06 6f ?? ?? ?? 0a dc 07 6f ?? ?? ?? 0a 13 07 16 2d bd}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AHEY_2147836106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AHEY!MTB"
        threat_id = "2147836106"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 06 1c 20 c3 00 00 00 9c 06 1a 20 80 00 00 00 9c 06 19 1d 9c 06 18 16 9c 06 1b 20 c3 00 00 00 9c 06 17 1f 57 9c 06 16}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AIMN_2147836503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AIMN!MTB"
        threat_id = "2147836503"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 16 13 08 2b 1d 07 06 11 08 9a 1f 10 28 ?? ?? ?? 0a 8c 56 00 00 01 6f ?? ?? ?? 0a 26 11 08 17 58 13 08 11 08 06 8e 69}  //weight: 2, accuracy: Low
        $x_1_2 = "Biblioteca" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABET_2147836677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABET!MTB"
        threat_id = "2147836677"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {03 04 1c d6 5d 8c ?? ?? ?? 01 02 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 0a 06 14 72 ?? ?? ?? 70 16 8d ?? ?? ?? 01 14 14 14 28 ?? ?? ?? 0a 74 ?? ?? ?? 1b 0b 73 ?? ?? ?? 0a 0c 08 07 03 1f 0b da}  //weight: 3, accuracy: Low
        $x_1_2 = "QQWESSSS" wide //weight: 1
        $x_1_3 = "InvokeMember" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NZR_2147836919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NZR!MTB"
        threat_id = "2147836919"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 08 02 08 91 03 08 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 00 08 17 58 0c 08 06 fe 04 0d 09 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 25 26 6f ?? ?? ?? 0a 00 de 02 2b 2d 08 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 11 04 16 73 ?? ?? ?? 0a 0d 09 07 6f ?? ?? ?? 0a 07 13 05 de 15 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 72 4d 00 00 70 12 00 73 2c 00 00 0a 80 03 00 00 04 06 3a 06 00 00 00 17 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 00 11 02 02 11 02 91 72 ?? 00 00 70 28 ?? 00 00 06 59 d2 9c 20 00 00 00 00 7e ?? 01 00 04 7b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 03 05 8e 69 5d 91 04 03 1f 16 5d 91 61 28 ?? ?? ?? 0a 05 03 17 58 05 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 13 07 16 13 06 2b 2f 11 07 11 06 9a 0c 08 6f ?? 00 00 0a 28 ?? 00 00 06 26 7e 0e 00 00 04 2c 02 de 1c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {25 26 0b 28 20 00 00 0a 25 26 07 16 07 8e 69 6f 21 00 00 0a 25 26 0a 28 1d 00 00 0a 25 26 06 6f 3b 00 00 0a 0c 1f 61 6a 08 28}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0e 11 1d 58 11 21 11 21 28 57 00 00 06 25 26 69 12 03 6f 31 00 00 06 25 26}  //weight: 2, accuracy: High
        $x_1_2 = "HVpOL.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {14 14 18 8d 01 00 00 01 25 16 09 74 07 00 00 01 28 ?? ?? ?? 06 17 9a a2 25 17 11 04 a2 28}  //weight: 2, accuracy: Low
        $x_1_2 = "ParserAr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {25 16 11 01 a2 25 13 02 14 14 17 8d 04 00 00 01 25 16 17 9c 25}  //weight: 2, accuracy: High
        $x_1_2 = "PoralPeril_StefanTicu" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 09 07 8e 69 5d 07 09 07 8e 69 5d 91 08 09 1f 16 5d 91 61 28 ?? ?? ?? 0a 07 09 17 58 07 8e 69 5d 91 28}  //weight: 2, accuracy: Low
        $x_1_2 = "TestFirstWFapp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0d 16 13 04 2b 16 09 11 04 08 11 04 9a 1f 10 28 a3 00 00 0a 9c 11 04 17 d6 13 04 00 11 04 20 00 c2 00 00 fe 04 13 06 11 06 2d db}  //weight: 2, accuracy: High
        $x_1_2 = "PokemonSystem" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 16 13 05 2b 1a 08 11 05 07 11 05 9a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d d9}  //weight: 2, accuracy: Low
        $x_1_2 = "FolderToText" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 15 07 11 06 06 11 06 9a 1f 10 28 ?? ?? ?? 0a 9c 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d de}  //weight: 2, accuracy: Low
        $x_1_2 = "_2048WindowsFormsApp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 13 04 2b 1f 00 02 11 04 09 6f 09 00 00 0a 13 05 08 11 04 09 11 05 6f 10 00 00 0a 00 00 11 04 17 58 13 04 11 04 06 fe 04 13 06 11 06 2d d6}  //weight: 1, accuracy: High
        $x_1_2 = {13 06 11 06 16 fe 02 13 07 11 07 2c 0f 00 11 05 11 04 16 11 06 6f 17 00 00 0a 00 00 00 11 06 16 fe 02 13 08 11 08 2d c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0d 2b 20 00 07 09 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 13 05 08 11 05 6f ?? ?? ?? 0a 00 09 18 58 0d 00 09 07 6f ?? ?? ?? 0a fe 04 13 06 11 06 2d d1}  //weight: 2, accuracy: Low
        $x_1_2 = "FormQuanLyBanHang" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 16 58 0a 2b 48 06 11 04 5d 13 06 06 11 08 5d 13 0b 07 11 06 91 13 0c 11 05 11 0b 6f ?? ?? ?? 0a 13 0d 07 06 17 58 11 04 5d 91 13 0e 11 0c 11 0d 61 11 0e 59 20 00 01 00 00 58 13 0f 07 11 06 11 0f 20 00 01 00 00 5d d2 9c 06 17 59 0a 06 16 fe 04 16 fe 01 13 10 11 10 2d ab}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 06 2b 42 00 07 11 06 07 8e 69 5d 07 11 06 07 8e 69 5d 91 08 11 06 1f 16 5d 91 61 28 ?? ?? ?? 0a 07 11 06 17 58 07 8e 69 5d 91}  //weight: 2, accuracy: Low
        $x_1_2 = "Network Simulation Tools" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_18
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 20 2b 28 00 11 1e 11 20 18 6f ?? ?? ?? 0a 20 03 02 00 00 28 ?? ?? ?? 0a 13 22 11 1f 11 22 6f ?? ?? ?? 0a 00 11 20 18 58 13 20 00 11 20 11 1e 6f ?? ?? ?? 0a fe 04 13 23 11 23 2d c7}  //weight: 2, accuracy: Low
        $x_1_2 = "evolutionSoccer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_19
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 05 16 13 07 2b 61 11 05 11 07 6f ?? ?? ?? 0a 1f 77 33 06 11 04 17 59 13 04 11 05 11 07 6f ?? ?? ?? 0a 1f 61 33 04 09 17 59 0d 11 05 11 07 6f ?? ?? ?? 0a 1f 73 33 06 11 04 17 58 13 04 11 05 11 07 6f ?? ?? ?? 0a 1f 64 33 04 09 17 58 0d 02}  //weight: 2, accuracy: Low
        $x_1_2 = "Tower Defense" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_20
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 11 0a 11 09 6f ?? ?? ?? 0a 13 0b 16 13 0c 11 05 11 08 9a 72 46 04 00 70 28 ?? ?? ?? 0a 13 0d 11 0d 2c 0d 00 12 0b 28 ?? ?? ?? 0a 13 0c 00 2b 42 11 05 11 08 9a 72 4a 04 00 70 28 ?? ?? ?? 0a 13 0e 11 0e 2c 0d 00 12 0b 28 ?? ?? ?? 0a 13 0c 00 2b 20 11 05 11 08 9a 72 4e 04 00 70 28 ?? ?? ?? 0a 13 0f 11 0f 2c 0b 00 12 0b 28 ?? ?? ?? 0a 13 0c 00 07 11 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_21
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {26 00 11 05 7b 15 00 00 04 28 ?? ?? ?? 0a 25 26 28 ?? ?? ?? 0a 25 26 6f ?? ?? ?? 0a 00 de 05}  //weight: 2, accuracy: Low
        $x_1_2 = "C:\\Users\\Administrator\\Documents\\CryptoObfuscator_Output\\HVpOL.pdb" ascii //weight: 1
        $x_1_3 = "HVpOL.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_22
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 2b 36 12 01 28 ?? ?? ?? 0a 0c 00 06 12 03 fe 15 05 00 00 02 12 03 12 02 28 ?? ?? ?? 0a 7d 04 00 00 04 12 03 12 02 28 ?? ?? ?? 0a 7d 05 00 00 04 09 6f ?? ?? ?? 0a 00 00 12 01 28}  //weight: 2, accuracy: Low
        $x_2_2 = {0d 2b 26 12 03 28 ?? ?? ?? 0a 13 04 00 08 07 11 04 7b 04 00 00 04 11 04 7b 05 00 00 04 8c 2a 00 00 01 6f ?? ?? ?? 0a 26 00 12 03 28}  //weight: 2, accuracy: Low
        $x_1_3 = "ResumeFormatDetector.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AF_2147836990_23
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AF!MTB"
        threat_id = "2147836990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 21 00 00 04 25 2d 17 26 7e 20 00 00 04 fe 06 36 00 00 06 73 10 00 00 0a 25 80 21 00 00 04 0a 72 5d 01 00 70 28 ?? ?? ?? 0a 0b 06 07 6f ?? ?? ?? 0a 0c 02 8e 69 8d ?? ?? ?? 01 0d 08 02 16 02 8e 69 09 16 6f ?? ?? ?? 0a 13 04 09 11 04}  //weight: 2, accuracy: Low
        $x_1_2 = "An experimental web browser that uses innovative technology" wide //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABFY_2147837424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABFY!MTB"
        threat_id = "2147837424"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 11 05 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 17 6f ?? ?? ?? 0a 00 08 09 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 06 00 11 06 02 16 02 8e 69 6f ?? ?? ?? 0a 00 11 06 6f ?? ?? ?? 0a 00 00 de 0d 11 06 2c 08 11 06 6f ?? ?? ?? 0a 00 dc 08 6f ?? ?? ?? 0a 0a 00 de 0b}  //weight: 2, accuracy: Low
        $x_1_2 = "god.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AHL_2147837453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AHL!MTB"
        threat_id = "2147837453"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 11 07 07 11 07 9a 1f 10 28 ?? ?? ?? 0a 9c 11 07 17 d6 13 07 11 07 07 8e 69 fe 04 13 08 11 08}  //weight: 2, accuracy: Low
        $x_1_2 = "TabControlExtra" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AGD_2147837454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AGD!MTB"
        threat_id = "2147837454"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 16 13 07 2b 41 08 11 07 72 0f 0e 00 70 28 ?? ?? ?? 0a 72 2d 0e 00 70 20 00 01 00 00 14 14 18 8d 1e 00 00 01 25 16 07 11 07 9a a2 25 17 1f 10}  //weight: 2, accuracy: Low
        $x_1_2 = "WindowsFormsApp1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NFD_2147837610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NFD!MTB"
        threat_id = "2147837610"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 6f 1c 01 00 06 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 17 1d 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "DeleteDirectoryOption" ascii //weight: 1
        $x_1_3 = "CoJ2Controller.Resources" wide //weight: 1
        $x_1_4 = "setup_ModsCoj" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AIKN_2147837821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AIKN!MTB"
        threat_id = "2147837821"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 16 13 07 2b 15 08 11 07 07 11 07 9a 1f 10 28 ?? ?? ?? 0a 9c 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08}  //weight: 2, accuracy: Low
        $x_1_2 = "Game_of_Pig" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ACM_2147837825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ACM!MTB"
        threat_id = "2147837825"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 16 13 04 2b 1e 08 11 04 9a 13 08 09 11 08 1f 10 28 ?? ?? ?? 0a b4 6f ?? ?? ?? 0a 00 11 04 17 d6 13 04 00 11 04 08 8e 69 fe 04 13 09 11 09}  //weight: 2, accuracy: Low
        $x_1_2 = "W2PizzaOrder" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ACM_2147837825_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ACM!MTB"
        threat_id = "2147837825"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 11 08 06 11 08 9a 1f 10 28 ?? ?? ?? 0a 9c 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09 2d de}  //weight: 2, accuracy: Low
        $x_1_2 = "NetworkCheckersWinForms" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AHNY_2147837826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AHNY!MTB"
        threat_id = "2147837826"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 16 4c 01 00 0c 2b 3c 00 06 08 06 8e 69 5d 06 08 06 8e 69 5d 91 07 08 1f 16 5d 91 61 28 ?? ?? ?? 0a 06 08 17 58 06 8e 69 5d 91}  //weight: 2, accuracy: Low
        $x_1_2 = "NetworkComunication" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AHNX_2147837827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AHNX!MTB"
        threat_id = "2147837827"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 15 fe 01 13 04 11 04 2c 12 00 02 28 ?? ?? ?? 06 07 6f ?? ?? ?? 06 0b 17 0c 2b 26 02 28 ?? ?? ?? 06 09 9a 08 16 32 03 16 2b 01 17 6f ?? ?? ?? 06 00 02 28 ?? ?? ?? 06 09 9a 07 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "Enigma" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AGDP_2147837828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AGDP!MTB"
        threat_id = "2147837828"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ssseee" ascii //weight: 1
        $x_1_2 = "Shahid" ascii //weight: 1
        $x_1_3 = "P#es.Wh#te" wide //weight: 1
        $x_1_4 = "Replace" ascii //weight: 1
        $x_1_5 = "System.Convert" wide //weight: 1
        $x_1_6 = "EsiniBulGame" wide //weight: 1
        $x_1_7 = "ToByte" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABHI_2147837964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABHI!MTB"
        threat_id = "2147837964"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 08 72 ?? ?? ?? 70 28 ?? ?? ?? 06 72 ?? ?? ?? 70 20 ?? ?? ?? 00 14 14 18 8d ?? ?? ?? 01 25 16 06 11 08 9a a2 25 17 1f 10 8c ?? ?? ?? 01 a2 28 ?? ?? ?? 06 a5 ?? ?? ?? 01 9c 11 08 17 58 13 08}  //weight: 5, accuracy: Low
        $x_1_2 = "Jumper.DCCC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBE_2147837987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBE!MTB"
        threat_id = "2147837987"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "         P#es.Wh#te          " wide //weight: 1
        $x_1_2 = "   Pi@s.Whit@ " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_FormBook_NZY_2147838091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NZY!MTB"
        threat_id = "2147838091"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 72 77 08 00 70 7e ?? 00 00 0a 72 81 08 00 70 28 ?? 00 00 0a 18 18 8d 14 00 00 01 25 16 03}  //weight: 1, accuracy: Low
        $x_1_2 = {47 00 65 00 74 00 50 00 00 09 69 00 78 00 65 00 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NZV_2147838127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NZV!MTB"
        threat_id = "2147838127"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$76d0656b-f0df-41e1-991d-49c6c757bfa7" ascii //weight: 10
        $x_1_2 = "DebuggableAttribute" ascii //weight: 1
        $x_1_3 = "DebuggingModes" ascii //weight: 1
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_FormBook_MBT_2147838232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBT!MTB"
        threat_id = "2147838232"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4D}5A}9!}&}!3}&}&}&}!4}&}&}&}FF}FF}&}&}B8}&}&}&}&}&}&}&}4!}&}&}" ascii //weight: 1
        $x_1_2 = "         P!es.Wh!te         " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBAA_2147838378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBAA!MTB"
        threat_id = "2147838378"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 11 05 16 11 05 8e 69 6f ?? 00 00 0a 13 06 de 59 09 2b cc 07 2b cb 6f ?? 00 00 0a 2b c6 13 04 2b c4 08 2b c3 11 04 2b c1 6f ?? 00 00 0a 2b bc 08 2b bb}  //weight: 1, accuracy: Low
        $x_1_2 = "Ilbvnyfkxqqhox" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NRE_2147838702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NRE!MTB"
        threat_id = "2147838702"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 28 16 00 00 0a 25 26 0b 28 ?? ?? ?? 0a 25 26 07 16 07 8e 69 6f ?? ?? ?? 0a 25 26 0a 28 ?? ?? ?? 0a 25 26 06 6f ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "JGFDSHTEJHDGSHJERFHDG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABJF_2147839122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABJF!MTB"
        threat_id = "2147839122"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 08 06 11 08 9a 1f 10 28 ?? ?? ?? 0a 9c 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09 2d de}  //weight: 5, accuracy: Low
        $x_1_2 = "PredictionScorer.RXAQQQQ" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AGVB_2147839133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AGVB!MTB"
        threat_id = "2147839133"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ToArray" ascii //weight: 1
        $x_1_2 = "GetPixel" ascii //weight: 1
        $x_1_3 = "Moserware2022" wide //weight: 1
        $x_1_4 = "Alor_22" ascii //weight: 1
        $x_1_5 = "brown" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AHFX_2147839137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AHFX!MTB"
        threat_id = "2147839137"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 1f 16 5d 91 61 28 ?? ?? ?? 0a 02 07 17 58 02 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 07 15 58}  //weight: 2, accuracy: Low
        $x_1_2 = "Zeta" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ARA_2147839171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ARA!MTB"
        threat_id = "2147839171"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 06 07 8e 69 5d 91 08 11 06 1f 16 5d 91 61 28 ?? ?? ?? 0a 07 11 06 17 58 07 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 06 15 58 13 06 11 06 16 fe 04 16 fe 01 13 07 11 07 2d b0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NF_2147839771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NF!MTB"
        threat_id = "2147839771"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2f 40 08 11 06 58 16 32 39 08 11 06 58 02}  //weight: 5, accuracy: High
        $x_5_2 = {1f 09 2e 32 03 07 59 28 ?? 00 00 0a 17 30 0b 04 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NF_2147839771_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NF!MTB"
        threat_id = "2147839771"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "JogoDasPalavras" ascii //weight: 2
        $x_2_2 = "$845fa7eb-2a60-48c5-9524-22d1b9dce946" ascii //weight: 2
        $x_2_3 = "FrmForca.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NF_2147839771_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NF!MTB"
        threat_id = "2147839771"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 26 11 0e 6a 59 69 28 ?? ?? ?? 06 25 26 13 10 20 ?? ?? ?? 00 38 ?? ?? ?? ff 07 16 6a 28 ?? ?? ?? 06 20 ?? ?? ?? 00 38 ?? ?? ?? ff 1b 45 ?? ?? ?? ?? ?? ?? ?? ff 20 ?? ?? ?? 00 28 ?? ?? ?? 06 39 ?? ?? ?? ff 26 06 28 ?? ?? ?? 06 25 26 69 13 0e 20 ?? ?? ?? 00 17}  //weight: 5, accuracy: Low
        $x_1_2 = "JUYTGFHJNK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NF_2147839771_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NF!MTB"
        threat_id = "2147839771"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 17 d6 0d 09 1f 10 31 08 1a 13 06 38 ?? ?? ?? ff 1c 2b f6 07 07 d8 20 ?? ?? ?? 00 d8 17 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 08 74 ?? ?? ?? 1b 07 28 ?? ?? ?? 06}  //weight: 5, accuracy: Low
        $x_1_2 = "A3hLoQ" wide //weight: 1
        $x_1_3 = "WindowsApp3.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBBK_2147839802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBBK!MTB"
        threat_id = "2147839802"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "G2D5H7R5ER47588857G754" wide //weight: 10
        $x_1_2 = "GetType" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "System.Activator" ascii //weight: 1
        $x_1_5 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_BAY_2147839809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.BAY!MTB"
        threat_id = "2147839809"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 2d 0c 15 2c 09 2b 75 17 3a ?? 00 00 00 26 1c 2c 3c 38 ?? 00 00 00 38 7b 00 00 00 38 ?? 00 00 00 1f 20 8d ?? 00 00 01 25 d0 ?? 00 00 04 2b 73 38 ?? 00 00 00 38 ?? 00 00 00 1f 10 8d 47 00 00 01 25}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABKY_2147841103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABKY!MTB"
        threat_id = "2147841103"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 11 07 07 11 07 9a 1f 10 28 ?? ?? ?? 0a d2 6f ?? ?? ?? 0a 00 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 2d d8}  //weight: 5, accuracy: Low
        $x_1_2 = "SystemManager.IJSFIHB" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AOF_2147841504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AOF!MTB"
        threat_id = "2147841504"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {25 16 11 04 a2 25 17 7e 17 00 00 0a a2 25 18 11 01 a2 25 19 17 8c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AOF_2147841504_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AOF!MTB"
        threat_id = "2147841504"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 34 2b 32 00 11 07 11 06 8e 69 5d 13 35 11 06 11 35 11 32 11 34 91 9c 03 11 32 11 34 91 6f ?? ?? ?? 0a 00 11 07 17 58 11 06 8e 69 5d 13 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AOF_2147841504_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AOF!MTB"
        threat_id = "2147841504"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7b 2a 00 00 04 72 92 07 00 70 6f ?? ?? ?? 0a 00 02 7b 2a 00 00 04 16 6f ?? ?? ?? 0a 00 73 7f 00 00 0a 0b 06 72 bc 07 00 70 6f ?? ?? ?? 0a 74 02 00 00 1b 0c 08}  //weight: 2, accuracy: Low
        $x_1_2 = "Prova" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AOF_2147841504_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AOF!MTB"
        threat_id = "2147841504"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 16 25 2d 1f 0a 2b 1b 13 04 1d 2c a9 2b c1 09 06 91 13 05 08 11 05 6f ?? ?? ?? 0a 06 17 58 16 2d f0 0a 06 09 8e 69 32 e6 08}  //weight: 2, accuracy: Low
        $x_1_2 = "FromBase64String" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFR_2147841577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFR!MTB"
        threat_id = "2147841577"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 6a 13 09 2b 53 00 11 09 1f 16 6a 5d 13 0a 07 11 09 07 8e 69 6a 5d d4 07 11 09 07 8e 69 6a 5d d4 91 08 11 0a 69 6f ?? 01 00 0a 61 07 11 09 17 6a 58 07 8e 69 6a 5d d4 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFR_2147841577_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFR!MTB"
        threat_id = "2147841577"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0a 11 04 20 ca 00 00 00 91 20 dd 00 00 00 59 0d 2b c3 02 03 06 04 05 28 ?? ?? ?? 06 06 17 58 0a 19 0d 2b b1}  //weight: 2, accuracy: Low
        $x_1_2 = {02 03 04 20 a4 02 00 00 20 a6 02 00 00 28 ?? 00 00 2b 0a 0e 04 05 6f ?? 00 00 0a 59 0b 19 0d 2b c5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFR_2147841577_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFR!MTB"
        threat_id = "2147841577"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 04 2b 6a 00 07 11 04 93 13 05 11 05 7e 40 00 00 04 8e 69 2f 0d 7e 40 00 00 04 11 05 93 16 fe 01 2b 01 17 13 06 11 06 2c 08 00 06 17 58 0a 00 2b 35 00 06 16 fe 02 13 07 11 07 2c 11 00 03 07 11 04 06 59 06 6f ?? ?? ?? 0a 26 16 0a 00 03 1f 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFR_2147841577_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFR!MTB"
        threat_id = "2147841577"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 19 11 06 5a 6f ?? ?? ?? 0a 13 07 11 07 1f 39 fe 02 13 09 11 09 2c 0d 11 07 1f 41 59 1f 0a 58 d1 13 07 2b 08 11 07 1f 30 59 d1 13 07 06 19 11 06 5a 17 58 6f ?? ?? ?? 0a 13 08 11 08 1f 39 fe 02 13 0a 11 0a 2c 0d 11 08 1f 41 59 1f 0a 58 d1 13 08 2b 08 11 08 1f 30 59 d1 13 08 08 11 06 1f 10 11 07 5a 11 08 58 d2 9c 00 11 06 17 58 13 06 11 06 07 fe 04 13 0b 11 0b 2d 84}  //weight: 2, accuracy: Low
        $x_1_2 = "Engine.ResourceP" wide //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AKR_2147841578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AKR!MTB"
        threat_id = "2147841578"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 17 5f 0d 2b 60 07 18 5f 17 63 13 04 2b 3f 06 02 09 11 04 6f ?? 01 00 06 13 05 04 03 6f ?? 00 00 0a 59 13 06 11 06 19 28 ?? 00 00 06 2c 0a 03 11 05 28 ?? 00 00 06 2b 0f 11 06 16 31 0a 03 11 05 11 06 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AKR_2147841578_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AKR!MTB"
        threat_id = "2147841578"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 16 13 05 2b 18 00 08 11 05 07 11 05 9a 1f 10 28 ?? ?? ?? 0a d2 9c 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d db}  //weight: 2, accuracy: Low
        $x_1_2 = "BeeTrial" wide //weight: 1
        $x_1_3 = "Melvin.White" wide //weight: 1
        $x_1_4 = "System.Reflection.Assembly" wide //weight: 1
        $x_1_5 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AOM_2147841579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AOM!MTB"
        threat_id = "2147841579"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 19 06 5a 6f ?? ?? ?? 0a 0b 07 1f 39 fe 02 13 09 11 09 2c 0b 07 1f 41 59 1f 0a 58 d1 0b 2b 06 07 1f 30 59 d1 0b 09 19 06 5a 17 58 6f ?? ?? ?? 0a 0c 08 1f 39 fe 02 13 0a 11 0a 2c 0b 08 1f 41 59 1f 0a 58 d1 0c 2b 06 08 1f 30 59 d1 0c 11 05 06 1f 10 07 5a 08 58 d2 9c 06 17 58 0a 06 11 04 fe 04 13 0b 11 0b 2d 98}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABKB_2147841604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABKB!MTB"
        threat_id = "2147841604"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 07 17 8d ?? ?? ?? 01 25 16 06 8c ?? ?? ?? 01 a2 14 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 06}  //weight: 4, accuracy: Low
        $x_1_2 = "Pontoon.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AAO_2147841948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AAO!MTB"
        threat_id = "2147841948"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 1d 2d 10 26 07 16 07 8e 69 17 2d 0a 26 26 26 07 0c de 21 0b 2b ee 28}  //weight: 2, accuracy: High
        $x_1_2 = "cpanelcustomershost.duckdns.org/SystemEnv/uploads/newsoftware-tester_Dygnflaf.jpg" wide //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AEW_2147842221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AEW!MTB"
        threat_id = "2147842221"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 16 13 06 2b 17 00 08 11 06 07 11 06 9a 1f 10 28 ?? ?? ?? 0a 9c 00 11 06 17 58 13 06 11 06 07 8e 69 fe 04 13 07 11 07 2d dc}  //weight: 2, accuracy: Low
        $x_1_2 = "WindowsFormsApplication6" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ALS_2147842222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ALS!MTB"
        threat_id = "2147842222"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 16 13 05 2b 17 00 08 11 05 07 11 05 9a 1f 10 28 ?? ?? ?? 0a 9c 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06}  //weight: 2, accuracy: Low
        $x_1_2 = "Cellular Automaton Simulation" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBCI_2147842727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBCI!MTB"
        threat_id = "2147842727"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 72 d5 05 00 70 72 d9 05 00 70 28 ?? 00 00 06 72 df 05 00 70 72 e3 05 00 70 6f ?? 00 00 0a 72 e9 05 00 70 72 ed 05 00 70 28 ?? 00 00 06 72 f3 05 00 70 72 f7 05 00 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBCI_2147842727_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBCI!MTB"
        threat_id = "2147842727"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$1cadc8fe-7cf8-4422-bfd9-29ad54ded78a" ascii //weight: 1
        $x_1_2 = "UniverseSimulator.Properties.Resources.resource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AMM_2147842895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AMM!MTB"
        threat_id = "2147842895"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 08 11 07 9a 0d 08 09 6f 35 00 00 0a 6f 24 00 00 0a 03 6f 89 00 00 0a 39 07 00 00 00 08 09 6f 8a 00 00 0a 11 07 17 d6 13 07 11 07 11 08 8e b7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AAK_2147843054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AAK!MTB"
        threat_id = "2147843054"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 06 2b 3f 11 06 1d 5d 16 fe 01 13 07 11 07 2c 18 11 04 07 17 6f ?? ?? ?? 0a 11 06 91 1d 61 b4 6f ?? ?? ?? 0a 00 00 2b 14 00 11 04 07 17 6f ?? ?? ?? 0a 11 06 91 6f ?? ?? ?? 0a 00 00 11 06 17 d6 13 06 11 06 11 05 31 bb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ACK_2147843057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ACK!MTB"
        threat_id = "2147843057"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 04 2b 1e 08 11 04 9a 13 08 09 11 08 1f 10 28 ?? ?? ?? 0a b4 6f ?? ?? ?? 0a 00 11 04 17 d6 13 04 00 11 04 08 8e 69 fe 04 13 09 11 09 2d d5}  //weight: 2, accuracy: Low
        $x_1_2 = "Z80NavBarControl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABPS_2147843313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABPS!MTB"
        threat_id = "2147843313"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {54 00 72 00 61 00 76 00 69 00 61 00 6e 00 47 00 61 00 6d 00 65 00 5f 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73}  //weight: 3, accuracy: High
        $x_3_2 = "TravianGame_WindowsForms.Properties.Resources" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFS_2147843550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFS!MTB"
        threat_id = "2147843550"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 13 05 2b 1a 00 09 11 05 08 11 05 91 07 11 05 07 8e 69 5d 91 61 d2 9c 00 11 05 17 58 13 05 11 05 08 8e 69 fe 04 13 06 11 06 2d d9}  //weight: 2, accuracy: High
        $x_1_2 = "WindowsForms.IMEHelper" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFS_2147843550_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFS!MTB"
        threat_id = "2147843550"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0d 2b 3f 00 16 13 04 2b 24 00 08 09 11 04 6f ?? ?? ?? 0a 13 0b 07 11 05 12 0b 28 ?? ?? ?? 0a 9c 11 05 17 58 13 05 00 11 04 17 58 13 04 11 04 08 6f ?? ?? ?? 0a fe 04 13 0c 11 0c 2d cc}  //weight: 2, accuracy: Low
        $x_1_2 = "Point_Of_Sale" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AAF_2147844013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AAF!MTB"
        threat_id = "2147844013"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {26 1a 8d 14 00 00 01 25 16 11 04 a2 25 17 7e 14 00 00 0a a2 25 18 07 a2 25 19 17 8c 04 00 00 01 a2 13 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AAF_2147844013_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AAF!MTB"
        threat_id = "2147844013"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 06 11 06 08 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 03 6a da 17 6a da 13 07 16 6a 13 08 2b 0f 07 1b 6f ?? ?? ?? 0a 00 11 08 17 6a d6 13 08 11 08 11 07 31 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AAF_2147844013_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AAF!MTB"
        threat_id = "2147844013"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0d 16 13 05 2b 1a 00 09 11 05 07 11 05 91 08 11 05 08 8e 69 5d 91 61 d2 9c 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d d9}  //weight: 2, accuracy: High
        $x_1_2 = "GroupProj" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AAF_2147844013_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AAF!MTB"
        threat_id = "2147844013"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7b 35 00 00 04 8e 69 17 59 8d 58 00 00 01 0b 02 7b 35 00 00 04 07 02 7b 35 00 00 04 8e 69 17 59 28 ?? ?? ?? 0a 11 04 16 8c 39 00 00 01 07 13 05 11 05 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "QLBanHang" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AAF_2147844013_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AAF!MTB"
        threat_id = "2147844013"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 20 2b 25 11 1e 11 20 18 28 ?? ?? ?? 06 20 03 02 00 00 28 ?? ?? ?? 0a 13 22 11 1f 11 22 6f ?? ?? ?? 0a 11 20 18 58 13 20 11 20 11 1e}  //weight: 2, accuracy: Low
        $x_1_2 = "Gastroenterology" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AAF_2147844013_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AAF!MTB"
        threat_id = "2147844013"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 8f 11 00 70 28 ?? ?? ?? 0a 0b 06 07 6f ?? ?? ?? 0a 0c 02 8e 69 8d ?? ?? ?? 01 0d 08 02 16 02 8e 69 09 16 6f ?? ?? ?? 0a 13 04 09 11 04}  //weight: 2, accuracy: Low
        $x_1_2 = "Web_Browser__HW_RGM_2012" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFI_2147844428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFI!MTB"
        threat_id = "2147844428"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 13 06 2b 1b 00 11 04 11 06 08 11 06 91 09 11 06 09 8e 69 5d 91 61 d2 9c 00 11 06 17 58 13 06 11 06 08 8e 69 fe 04 13 07 11 07 2d d8}  //weight: 2, accuracy: High
        $x_1_2 = "neurosim" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ASA_2147844460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ASA!MTB"
        threat_id = "2147844460"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 04 2b 26 00 08 11 04 18 6f ?? ?? ?? 0a 20 03 02 00 00 28 ?? ?? ?? 0a 13 06 09 11 06 6f ?? ?? ?? 0a 00 11 04 18 58 13 04 00 11 04 08 6f ?? ?? ?? 0a fe 04 13 07 11 07 2d ca}  //weight: 2, accuracy: Low
        $x_1_2 = "LTTQ_SUDOKU_GAME" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ASA_2147844460_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ASA!MTB"
        threat_id = "2147844460"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7b 09 00 00 04 72 59 02 00 70 6f ?? ?? ?? 0a 38 9a f8 ff ff 00 02 16 28 ?? ?? ?? 0a 38 62 05 00 00 00 02 7b 0b 00 00 04 6f ?? ?? ?? 0a 38 d7 fa ff ff 00 02 7b 12 00 00 04 6f ?? ?? ?? 0a 38 2a f4 ff ff 00 28}  //weight: 2, accuracy: Low
        $x_1_2 = "aDayAtTheRaces" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABNR_2147845032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABNR!MTB"
        threat_id = "2147845032"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0d 09 08 6f ?? ?? ?? 0a 00 09 18 6f ?? ?? ?? 0a 00 09 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a 13 04 11 04 02}  //weight: 5, accuracy: Low
        $x_1_2 = "H4FZTGCX87X48BF74GB588" wide //weight: 1
        $x_1_3 = "Kruskal.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ANF_2147845056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ANF!MTB"
        threat_id = "2147845056"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 05 2b 31 07 11 04 11 05 6f ?? ?? ?? 0a 13 08 07 11 04 11 05 6f ?? ?? ?? 0a 13 09 11 09 28 ?? ?? ?? 0a 13 0a 09 08 11 0a 28 ?? ?? ?? 0a 9c 11 05 17 58 13 05 11 05 07}  //weight: 2, accuracy: Low
        $x_1_2 = "BankMachine" wide //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFA_2147845223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFA!MTB"
        threat_id = "2147845223"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 09 07 08 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 13 05 11 05 11 04 17 73 ?? 00 00 0a 13 06 11 06 06 16 06 8e 69 6f ?? 00 00 0a 11 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFA_2147845223_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFA!MTB"
        threat_id = "2147845223"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0c 16 13 04 2b 1c 08 07 11 04 18 6f 52 00 00 0a 1f 10 28 53 00 00 0a 6f 54 00 00 0a 11 04 18 58 13 04 11 04 07 6f 0d 00 00 0a 32 da}  //weight: 2, accuracy: High
        $x_1_2 = "SudokuUI" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFA_2147845223_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFA!MTB"
        threat_id = "2147845223"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 16 16 fe 01 13 17 11 17 2c 03 17 13 16 09 11 14 07 11 14 91 11 04 11 15 95 61 d2 9c 00 11 14 17 58 13 14 11 14 07 8e 69 fe 04 13 18}  //weight: 3, accuracy: High
        $x_2_2 = {16 0a 16 0b 2b 11 00 02 07 06 03 04 28 ?? 00 00 06 0a 07 17 58 0b 00 07 20 00 01 00 00 fe 05 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_KAN_2147845370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.KAN!MTB"
        threat_id = "2147845370"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 05 08 6f ?? 00 00 0a 25 26 09}  //weight: 2, accuracy: Low
        $x_2_2 = {14 14 11 06}  //weight: 2, accuracy: High
        $x_2_3 = {25 26 26 1f}  //weight: 2, accuracy: High
        $x_2_4 = {06 25 26 28}  //weight: 2, accuracy: High
        $x_2_5 = {70 0a 06 28 ?? 00 00 0a 25 26 0b 28 ?? 00 00 0a 25 26 07 16 07 8e 69 6f ?? 00 00 0a 25 26 0a 28 ?? 00 00 0a 25 26 06 6f ?? 00 00 0a 25 26 0c}  //weight: 2, accuracy: Low
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFY_2147845476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFY!MTB"
        threat_id = "2147845476"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 13 04 2b 1f 00 08 07 11 04 18 6f fe 00 00 0a 1f 10 28 ff 00 00 0a 6f 00 01 00 0a 00 00 11 04 18 58 13 04 11 04 07 6f 24 00 00 0a fe 04 13 05 11 05 2d d1}  //weight: 2, accuracy: High
        $x_1_2 = "Sudoku" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABRQ_2147845551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABRQ!MTB"
        threat_id = "2147845551"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 06 72 ae 1d 00 70 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 00 07 06 72 b4 1d 00 70 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 00 07 06 72 ba 1d 00 70 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 00 07 06 72 c0 1d 00 70 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 00 02}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AJF_2147845583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AJF!MTB"
        threat_id = "2147845583"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 09 2b 36 00 11 06 11 09 09 11 09 91 11 05 61 11 04 11 07 91 61 28 ?? ?? ?? 0a 9c 11 07 1f 15 fe 01 13 0a 11 0a 2c 05 16 13 07 2b 06 11 07 17 58 13 07 00 11 09 17 58 13 09 11 09 09 8e 69 17 59 fe 02 16 fe 01 13 0b 11 0b 2d b8}  //weight: 2, accuracy: Low
        $x_1_2 = "Skylark" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFF_2147845654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFF!MTB"
        threat_id = "2147845654"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 06 2b 17 00 08 07 11 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 00 11 06 17 59 13 06 11 06 16 fe 04 16 fe 01 13 07 11 07 2d db}  //weight: 2, accuracy: Low
        $x_1_2 = "QuanLyBanVeMayBay" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFF_2147845654_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFF!MTB"
        threat_id = "2147845654"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 21 12 0a 28 ?? ?? ?? 0a 13 0b 2b 16 12 0a 28 ?? ?? ?? 0a 13 0b 2b 0b 12 0a 28 ?? ?? ?? 0a 13 0b 2b 00 07 11 0b 6f ?? ?? ?? 0a 00 00 11 09 17 58 13 09 11 09 09 fe 04 13 0e 11 0e 2d 97}  //weight: 2, accuracy: Low
        $x_1_2 = "Technite" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFF_2147845654_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFF!MTB"
        threat_id = "2147845654"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 04 2b 23 00 06 11 04 18 6f ?? ?? ?? 0a 13 05 07 11 04 18 5b 11 05 1f 10 28 ?? ?? ?? 0a d2 9c 00 11 04 18 58 13 04 11 04 06 6f ?? ?? ?? 0a fe 04 13 06 11 06 2d cd}  //weight: 2, accuracy: Low
        $x_1_2 = "QuanLyNhanSu" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFF_2147845654_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFF!MTB"
        threat_id = "2147845654"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0d 2b 28 00 07 09 18 6f ?? ?? ?? 0a 20 03 02 00 00 28 ?? ?? ?? 0a 13 05 08 11 05 8c 5b 00 00 01 6f ?? ?? ?? 0a 26 09 18 58 0d 00 09 07 6f ?? ?? ?? 0a fe 04 13 06 11 06 2d c9}  //weight: 2, accuracy: Low
        $x_1_2 = "SudokuGame" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFF_2147845654_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFF!MTB"
        threat_id = "2147845654"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 05 2b 2e 00 11 05 09 5d 13 08 11 05 09 5b 13 09 08 11 08 11 09 6f ?? ?? ?? 0a 13 0a 07 12 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 11 05 17 58 13 05 00 11 05 09 11 04 5a fe 04 13 0b 11 0b 2d c4}  //weight: 2, accuracy: Low
        $x_1_2 = "QL_KARAOKE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AGF_2147845655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AGF!MTB"
        threat_id = "2147845655"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 05 2b 27 00 07 11 04 11 05 6f ?? ?? ?? 0a 13 06 08 12 06 28 ?? ?? ?? 0a 8c 77 00 00 01 6f ?? ?? ?? 0a 26 00 11 05 17 58 13 05 11 05 07 6f ?? ?? ?? 0a fe 04 13 07 11 07 2d c9}  //weight: 2, accuracy: Low
        $x_1_2 = "AirFreight" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AGF_2147845655_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AGF!MTB"
        threat_id = "2147845655"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 07 2b 2d 00 11 05 11 07 18 6f ?? ?? ?? 0a 20 03 02 00 00 28 ?? ?? ?? 0a 13 09 11 06 11 09 8c 73 00 00 01 6f ?? ?? ?? 0a 26 11 07 18 58 13 07 00 11 07 11 05 6f ?? ?? ?? 0a fe 04 13 0a 11 0a 2d c2}  //weight: 2, accuracy: Low
        $x_1_2 = "PuzzleManagement" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ACA_2147845731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ACA!MTB"
        threat_id = "2147845731"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 0d 2b 23 00 07 09 18 6f c4 00 00 0a 20 03 02 00 00 28 c5 00 00 0a 13 05 08 11 05 6f c6 00 00 0a 00 09 18 58 0d 00 09 07 6f c7 00 00 0a fe 04 13 06 11 06 2d ce}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABSP_2147845757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABSP!MTB"
        threat_id = "2147845757"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 07 11 04 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 11 04 18 58 13 04 11 04 07 6f ?? 00 00 0a fe 04 13 05 11 05 2d d1}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AZF_2147845846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AZF!MTB"
        threat_id = "2147845846"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 16 2b 28 00 11 14 11 16 18 6f ?? ?? ?? 0a 20 03 02 00 00 28 ?? ?? ?? 0a 13 18 11 15 11 18 6f ?? ?? ?? 0a 00 11 16 18 58 13 16 00 11 16 11 14 6f ?? ?? ?? 0a fe 04 13 19 11 19 2d c7}  //weight: 2, accuracy: Low
        $x_1_2 = "MorissCode" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABTZ_2147845879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABTZ!MTB"
        threat_id = "2147845879"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 13 20 2b 25 11 1e 11 20 18 28 ?? ?? 00 06 20 03 02 00 00 28 ?? 00 00 0a 13 22 11 1f 11 22 6f ?? 00 00 0a 11 20 18 58 13 20 11 20 11 1e 28 ?? ?? 00 06 32 d0}  //weight: 4, accuracy: Low
        $x_1_2 = "Gastroenterology.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABUA_2147845880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABUA!MTB"
        threat_id = "2147845880"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 1d 11 1f 18 6f ?? 00 00 0a 20 03 02 00 00 28 ?? 00 00 0a 13 21 11 1e 11 21 6f ?? 00 00 0a 00 11 1f 18 58 13 1f 00 11 1f 11 1d 6f ?? 00 00 0a fe 04 13 22 11 22 2d c7}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABUB_2147845941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABUB!MTB"
        threat_id = "2147845941"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 13 07 2b 1f 00 09 08 11 07 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 11 07 18 58 13 07 11 07 08 6f ?? 00 00 0a fe 04 13 08 11 08 2d d1}  //weight: 4, accuracy: Low
        $x_1_2 = "GameXO.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABUJ_2147846123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABUJ!MTB"
        threat_id = "2147846123"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0d 2b 20 00 07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 13 07 08 11 07 6f ?? 00 00 0a 00 09 18 58 0d 00 09 07 6f ?? 00 00 0a fe 04 13 08 11 08 2d d1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABUK_2147846139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABUK!MTB"
        threat_id = "2147846139"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {18 da 13 07 16 13 08 2b 23 08 09 07 11 08 18 6f ?? 01 00 0a 1f 10 28 ?? ?? 00 0a b4 6f ?? ?? 00 0a 00 09 17 d6 0d 11 08 18 d6 13 08 11 08 11 07 31 d7}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NFH_2147846188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NFH!MTB"
        threat_id = "2147846188"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {04 6f bf 00 00 0a 0a 06 74 36 00 00 01 0b 2b 00 07 2a}  //weight: 5, accuracy: High
        $x_1_2 = "Auty 2" ascii //weight: 1
        $x_1_3 = "rtbBSDR" ascii //weight: 1
        $x_1_4 = "AlgorithmSimulator.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBCN_2147846391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBCN!MTB"
        threat_id = "2147846391"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 13 05 08 11 05 6f ?? 00 00 0a 00 09 18 58 0d 00 09 07 6f ?? 00 00 0a fe 04 13 06 11 06 2d d1}  //weight: 1, accuracy: Low
        $x_1_2 = {72 94 0f 00 70 06 72 a8 0f 00 70 6f ?? 00 00 0a 74 ?? 00 00 01 72 ae 0f 00 70 72 4e 0c 00 70}  //weight: 1, accuracy: Low
        $x_1_3 = "Pendulum.Canvas" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABUR_2147846397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABUR!MTB"
        threat_id = "2147846397"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Bearing_Machine.Properties.Resources.resources" ascii //weight: 2
        $x_2_2 = "Bearing_Machine.System_Output.resources" ascii //weight: 2
        $x_1_3 = "6ffcd28a-d54e-4560-b928-d4ccba896563" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABSC_2147846499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABSC!MTB"
        threat_id = "2147846499"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "WindowsFormsApplication6.Openingscreen.resources" ascii //weight: 4
        $x_1_2 = "WindowsFormsApplication6.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AGK_2147847586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AGK!MTB"
        threat_id = "2147847586"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0d 2b 3f 00 16 13 04 2b 24 00 08 09 11 04 6f ?? ?? ?? 0a 13 0b 07 11 05 12 0b 28 ?? ?? ?? 0a 9c 11 05 17 58 13 05 00 11 04 17 58 13 04 11 04 08 6f ?? ?? ?? 0a fe 04 13 0c 11 0c 2d cc}  //weight: 2, accuracy: Low
        $x_1_2 = "QuanLyBanCoffee1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MAAE_2147847755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MAAE!MTB"
        threat_id = "2147847755"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 07 11 07 9a 1f 10 7e ?? 00 00 04 28 ?? ?? ?? 06 86 6f ?? 00 00 0a 00 11 07 17 d6 13 07 11 07 11 06}  //weight: 1, accuracy: Low
        $x_1_2 = {72 40 21 04 70 72 44 21 04 70 7e ?? 00 00 04 28 ?? ?? 00 06 72 48 21 04 70 72 4c 21 04 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MAAG_2147847803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MAAG!MTB"
        threat_id = "2147847803"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 09 09 5d 13 0a 11 09 09 5b 13 0b 08 11 0a 11 0b 6f ?? 00 00 0a 13 0c 07 11 05 12 0c 28 ?? 00 00 0a 9c 11 05 17 58 13 05 00 11 09 17 58 13 09 11 09 09 11 04 5a fe 04 13 0d 11 0d 2d c1}  //weight: 1, accuracy: Low
        $x_1_2 = "lo.A4" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABYF_2147847908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABYF!MTB"
        threat_id = "2147847908"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0a 2b 29 06 08 5d 13 09 06 08 5b 13 0a 07 11 09 11 0a 6f ?? 00 00 0a 13 0d 11 04 09 12 0d 28 ?? 00 00 0a 9c 09 17 58 0d 06 17 58 0a 06 08 11 06 5a fe 04 13 0b 11 0b 2d ca}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MAAH_2147848148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MAAH!MTB"
        threat_id = "2147848148"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 08 06 08 06 8e 69 5d 91 03 08 91 61 d2 9c 00 08 17 58 0c 08 03 8e 69 fe 04 0d 09 2d e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AIY_2147848236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AIY!MTB"
        threat_id = "2147848236"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 02 50 8e 69 17 59 0b ?? ?? ?? ?? ?? 02 50 06 91 0c 02 50 06 02 50 07 91 9c 02 50 07 08 9c 06 17 58 0a 07 17 59 0b 06 07 32 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MAAO_2147848261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MAAO!MTB"
        threat_id = "2147848261"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "00-E6-00-96-00-B2-00-67-00-27-00-75-00-" wide //weight: 1
        $x_1_2 = "66-00-F6-00-93-00-66-00-93-00-83-00-67-" wide //weight: 1
        $x_1_3 = "$be18e070-fb24-4b4d-b6c0-608d6c49491a" ascii //weight: 1
        $x_1_4 = "ConsoleApp.Properties.Resources.resource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_Y_2147848900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.Y!MTB"
        threat_id = "2147848900"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 05 11 02 6f}  //weight: 2, accuracy: High
        $x_2_2 = {14 14 11 06 74 ?? 00 00 1b 6f ?? 00 00 0a 26}  //weight: 2, accuracy: Low
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_GJF_2147848906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.GJF!MTB"
        threat_id = "2147848906"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {16 0a 2b 17 00 00 0f 00 28 ?? ?? ?? 0a 0b 07 06 58 03 06 91 52 00 00 06 17 58 0a 06 03 8e 69 fe 04 0c 08 2d df}  //weight: 10, accuracy: Low
        $x_1_2 = "12HLFYWww2h5st9yaTMylg" ascii //weight: 1
        $x_1_3 = "OHTbcwX4K0BZRNDq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ARK_2147848995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ARK!MTB"
        threat_id = "2147848995"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {14 14 17 8d 16 00 00 01 25 16 07 a2 6f ?? ?? ?? 0a 75 1d 00 00 01 0c 08 6f ?? ?? ?? 0a 16 9a 6f ?? ?? ?? 0a 18 9a 0d 09 16 8c 58 00 00 01 02 7b 0e 00 00 04 13 04 11 04 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "QuanLiThuVien" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABZY_2147849003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABZY!MTB"
        threat_id = "2147849003"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 1f 09 5d 16 fe 01 0d 09 2c 40 02 17 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 04 02 18 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 1f 09 61 8c ?? 00 00 01 a2 14 28 ?? 01 00 0a 07 17 d6 0b 07 08 fe 04 13 05 11 05 2d a7}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBEH_2147849183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBEH!MTB"
        threat_id = "2147849183"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {38 00 38 00 38 00 42 00 47 00 37 00 34 00 35 00 37 00 35 00 34 00 50 00 47 00 41 00 47 00 42 00 34 00 45 00 34 00 38 00 4e 00 39 00 00 13 69 00 64 00 50 00 70 00 75 00 48 00 59 00 31 00 39}  //weight: 1, accuracy: High
        $x_1_2 = "psa" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBEH_2147849183_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBEH!MTB"
        threat_id = "2147849183"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 11 0a 11 09 6f ?? 00 00 0a 13 0b 16 13 0c 11 05 11 08 9a 72 86 0e 00 70 28 ?? 00 00 0a 13 0d 11 0d 2c 0d 00 12 0b 28 ?? 00 00 0a 13 0c 00 2b 42 11 05 11 08 9a 72 8a 0e 00 70 28 ?? 00 00 0a 13 0e 11 0e 2c 0d 00 12 0b 28 ?? 00 00 0a 13 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBEX_2147849634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBEX!MTB"
        threat_id = "2147849634"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 07 11 08 d4 07 11 08 d4 91 11 06 11 06 09 95 11 06 11 04 95 58 20 ff 00 00 00 5f 95 61 d2 9c 11 08 17 6a 58 13 08 11 08 11 07 8e 69 17 59 6a 31 9f}  //weight: 1, accuracy: High
        $x_1_2 = "tQ.MI" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AADD_2147849724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AADD!MTB"
        threat_id = "2147849724"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 08 2b 35 00 11 05 11 08 08 11 08 91 11 04 61 09 11 06 91 61 28 ?? 00 00 0a 9c 11 06 1f 15 fe 01 13 09 11 09 2c 05 16 13 06 2b 06 11 06 17 58 13 06 00 11 08 17 58 13 08 11 08 08 8e 69 17 59 fe 02 16 fe 01 13 0a 11 0a 2d b9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AADE_2147849737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AADE!MTB"
        threat_id = "2147849737"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {09 17 58 20 ff 00 00 00 5f 0d 11 04 11 06 09 95 58 20 ff 00 00 00 5f 13 04 11 06 09 95 13 05 11 06 09 11 06 11 04 95 9e 11 06 11 04 11 05 9e 11 07 11 08 d4 07 11 08 d4 91 11 06 11 06 09 95 11 06 11 04 95 58 20 ff 00 00 00 5f 95 61 d2 9c 11 08 17 6a 58 13 08 11 08 11 07 8e 69 17 59 6a 31 9f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AADG_2147849745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AADG!MTB"
        threat_id = "2147849745"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 04 2b 24 00 08 09 11 04 6f ?? 00 00 0a 13 0b 07 11 05 12 0b 28 ?? 00 00 0a 9c 11 05 17 58 13 05 00 11 04 17 58 13 04 11 04 08 6f ?? 00 00 0a fe 04 13 0c 11 0c 2d cc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBGQ_2147850569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBGQ!MTB"
        threat_id = "2147850569"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 16 0a 2b 19 07 06 08 06 18 5a 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a d2 9c 06 17 58 0a 06 07 8e 69 fe 04 13 05 11 05 2d db}  //weight: 1, accuracy: Low
        $x_1_2 = "QUANLYDAILY.Properties.Resources.resource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AAB_2147850639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AAB!MTB"
        threat_id = "2147850639"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 08 2b 44 00 16 13 09 2b 2c 00 09 11 04 11 08 58 11 07 11 09 58 6f ?? ?? ?? 0a 13 0a 12 0a 28 ?? ?? ?? 0a 13 0b 08 07 11 0b 9c 07 17 58 0b 11 09 17 58 13 09 00 11 09 17 fe 04 13 0c 11 0c 2d c9}  //weight: 2, accuracy: Low
        $x_1_2 = "Biosim" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AADJ_2147850996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AADJ!MTB"
        threat_id = "2147850996"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "QuanLyBanCoffee1.Properties.Resources" ascii //weight: 2
        $x_2_2 = "QuanLyBanCoffee1.FormLoading.resources" ascii //weight: 2
        $x_1_3 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ATU_2147851140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ATU!MTB"
        threat_id = "2147851140"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 05 2b 3c 00 07 11 05 07 8e 69 5d 07 11 05 07 8e 69 5d 91 08 11 05 1f 16 5d 6f ?? ?? ?? 0a 61 07 11 05 17 58 07 8e 69 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 00 11 05 15 58 13 05 11 05 16 fe 04 16 fe 01 13 06 11 06 2d b6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ATU_2147851140_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ATU!MTB"
        threat_id = "2147851140"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {a2 25 17 11 07 8c 46 00 00 01 a2 28 ?? ?? ?? 0a a5 19 00 00 01 13 08 12 08 28 ?? ?? ?? 0a 13 09 07 11 09 6f ?? ?? ?? 0a 00 00 11 05 17 58 13 05 11 05 08}  //weight: 2, accuracy: Low
        $x_1_2 = "CrosshairNet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AAGW_2147851444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AAGW!MTB"
        threat_id = "2147851444"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 01 00 00 70 28 ?? 00 00 0a 0a 06 28 ?? 00 00 06 0b 07 02 28 ?? 00 00 06 0c 2b 00 08 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "CYtzHLkrHAkRalizuL9TqbViN2pf3gZuqjcSFSH8/0w=" wide //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBHE_2147851804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBHE!MTB"
        threat_id = "2147851804"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 20 00 01 00 00 6f ?? 02 00 0a 06 20 ?? ?? ?? ?? 28 ?? 01 00 06 28 ?? 02 00 0a 6f ?? 02 00 0a 06 20 ?? ?? ?? ?? 28 ?? 01 00 06 28 ?? 02 00 0a 6f ?? 02 00 0a 06 06 6f ?? 02 00 0a 06}  //weight: 1, accuracy: Low
        $x_1_2 = {06 20 00 01 00 00 6f ?? 00 00 0a 06 20 ?? ?? ?? ?? 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 20 ?? ?? ?? ?? 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 13 06 14 0b 2b 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_FormBook_NFA_2147851879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NFA!MTB"
        threat_id = "2147851879"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 28 40 00 00 0a 0a 28 ?? ?? ?? 0a 06 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 0b 2b 00 07 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "androZid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AAGN_2147851998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AAGN!MTB"
        threat_id = "2147851998"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d8bcf6db-f8af-44a6-9f3b-b4bd29a83a99" ascii //weight: 1
        $x_1_2 = "WhamoLauncher.Charts" wide //weight: 1
        $x_1_3 = "Gas Natural Fenosa" wide //weight: 1
        $x_1_4 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AJI_2147852397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AJI!MTB"
        threat_id = "2147852397"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 2b 2d 06 6f 12 00 00 0a 74 0f 00 00 01 0b 07 6f 13 00 00 0a 6f 14 00 00 0a 02 6f 14 00 00 0a 6f 15 00 00 0a 2c 09 07 6f 16 00 00 0a 0c de 22 06 6f 17 00 00 0a 2d cb}  //weight: 2, accuracy: High
        $x_1_2 = "BlackMail_ProcessedByFody" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AGMP_2147852750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AGMP!MTB"
        threat_id = "2147852750"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 2b 35 06 07 06 8e 69 5d 06 07 06 8e 69 5d 91 11 04 07 1f 16 5d 6f ?? ?? ?? 0a 61 06 07 17 58 06 8e 69 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 07 15 58 0b 07 16 fe 04 16 fe 01 13 07 11 07 2d be}  //weight: 2, accuracy: Low
        $x_1_2 = "QLCHApple_BUS" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AJJW_2147852929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AJJW!MTB"
        threat_id = "2147852929"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 04 2b 4d 00 11 04 07 8e 69 5d 13 05 07 11 05 91 13 06 08 11 04 1f 16 5d 6f ?? ?? ?? 0a d2 13 07 07 11 04 17 58 07 8e 69 5d 91 13 08 11 06 11 07 61 11 08 20 00 01 00 00 58 20 00 01 00 00 5d 59 13 09 07 11 05 11 09 d2 9c 00 11 04 17 59 13 04 11 04 16 fe 04 16 fe 01 13 0a 11 0a 2d a5}  //weight: 2, accuracy: Low
        $x_1_2 = "BankingSystemSimulation" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AAMJ_2147888657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AAMJ!MTB"
        threat_id = "2147888657"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 8c 04 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 02 28 ?? 00 00 06 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "jA4V2waKVG+8JgkdBbrCepqzB97/t/68xoVL+iU1fsg=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AAMQ_2147888823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AAMQ!MTB"
        threat_id = "2147888823"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {10 01 0f 01 03 8e 69 18 59 28 ?? 00 00 2b 00 d0 ?? 00 00 01 28 ?? 00 00 0a 72 75 00 00 70 20 00 01 00 00 14 14 17 8d ?? 00 00 01 25 16 02}  //weight: 4, accuracy: Low
        $x_1_2 = "Buta" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AWO_2147890048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AWO!MTB"
        threat_id = "2147890048"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 16 0b 16 0c 2b 4e 00 02 08 6f 4a 00 00 0a 0d 09 20 a7 00 00 00 fe 01 13 04 11 04 2c 32 00 02 07 08 07 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AJSM_2147891572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AJSM!MTB"
        threat_id = "2147891572"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 5a 1f 16 58 0a 2b 43 06 03 8e 69 5d 0b 06 04 6f ?? ?? ?? 0a 5d 0c 03 07 91 0d 04 08 6f ?? ?? ?? 0a 13 04 02 03 06 28 ?? ?? ?? 06 13 05 02 09 11 04 11 05 28 ?? ?? ?? 06 13 06 03 07 11 06 20 00 01 00 00 5d d2 9c 06 17 59 0a 06 16 fe 04 16 fe 01 13 07 11 07 2d b0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NFG_2147892298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NFG!MTB"
        threat_id = "2147892298"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 74 bc 00 00 02 6f ?? ?? 00 06 0a 02 06 17 6f ?? ?? 00 06 0b 02 6f ?? ?? 00 06 0c 02 08 07 6f ?? ?? 00 06 2c 08 02 08}  //weight: 5, accuracy: Low
        $x_1_2 = "Aolmgmcftoglcrugqburaane" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NFK_2147892369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NFK!MTB"
        threat_id = "2147892369"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 74 00 00 0a 28 ?? ?? 00 2b 0d 09 1f 10 28 ?? ?? 00 2b 09 6f ?? ?? 00 0a 1f 10 59 28 ?? ?? 00 2b 73 ?? ?? 00 0a 13 04 d0 ?? ?? 00 01 28 ?? ?? 00 0a 72 ?? ?? 00 70 20 ?? ?? 00 00 14 14 17 8d ?? ?? 00 01 25 16 11 04 6f ?? ?? 00 0a a2 28 ?? ?? 00 0a 74 ?? ?? 00 01}  //weight: 5, accuracy: Low
        $x_1_2 = "XigGSm.g.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AASC_2147892780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AASC!MTB"
        threat_id = "2147892780"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0b 06 73 ?? 00 00 0a 13 04 11 04 11 06 16 73 ?? 00 00 0a 13 05 11 05 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 28 ?? 00 00 06 dd ?? 00 00 00 11 05 6f ?? 00 00 0a dc}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABK_2147892845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABK!MTB"
        threat_id = "2147892845"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b4 9c 00 2b 0d 00 07 11 04 07 11 04 91 17 da b4 9c 00 11 04 17 d6 13 04 11 04 09 31 ae}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABK_2147892845_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABK!MTB"
        threat_id = "2147892845"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0a 2b 28 16 0b 2b 0e 02 06 07 03 04 28 ?? 00 00 06 07 17 58 0b 07 02 6f ?? 00 00 0a 2f 09 03 6f ?? 00 00 0a 04 32 e0}  //weight: 2, accuracy: Low
        $x_1_2 = {02 03 04 6f ?? 00 00 0a 0e 04 05 6f ?? 00 00 0a 59 0a 06 05 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABK_2147892845_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABK!MTB"
        threat_id = "2147892845"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 16 58 0b 2b 49 07 06 8e 69 5d 13 04 07 09 6f ?? ?? ?? 0a 5d 13 09 06 11 04 91 13 0a 09 11 09 6f ?? ?? ?? 0a 13 0b 02 06 07 28 ?? ?? ?? 06 13 0c 02 11 0a 11 0b 11 0c 28 ?? ?? ?? 06 13 0d 06 11 04 02 11 0d 28 ?? ?? ?? 06 9c 07 17 59 0b 07 16 fe 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ASFO_2147895247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ASFO!MTB"
        threat_id = "2147895247"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 07 07 8e 69 6a 5d d4 07 11 07 07 8e 69 6a 5d d4 91 08 11 07 08 8e 69 6a 5d d4 91 61 28 ?? 00 00 06 07 11 07 17 6a 58 07 8e 69 6a 5d d4 91 28 ?? 00 00 06 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? 00 00 06 9c 11 07 17 6a 58 13 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AAVI_2147895251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AAVI!MTB"
        threat_id = "2147895251"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0b 07 18 8c ?? 00 00 01 28 ?? 00 00 0a a5 ?? 00 00 01 6f ?? 00 00 0a 00 07 18 8c ?? 00 00 01 28 ?? 00 00 0a a5 ?? 00 00 01 6f ?? 00 00 0a 00 07 72 01 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 0c 08 06 16 06 8e 69 6f ?? 00 00 0a 0d}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AAVJ_2147895252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AAVJ!MTB"
        threat_id = "2147895252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 00 20 7b 82 e5 cc 28 ?? 00 00 06 28 ?? 00 00 06 20 5c 82 e5 cc 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 13 07}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ASFP_2147895298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ASFP!MTB"
        threat_id = "2147895298"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 11 04 02 11 04 91 07 61 06 09 91 61 28 ?? 00 00 0a 9c 09 03 8e 69 17 59 33 04 16 0d 2b 04 09 17 58 0d 11 04 17 58 13 04 11 04 02 8e 69 17 59 31}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AAVN_2147895400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AAVN!MTB"
        threat_id = "2147895400"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 0b 72 37 00 00 70 28 ?? 00 00 0a 72 69 00 00 70 28 ?? 00 00 06 6f ?? 00 00 0a 13 01}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBEP_2147895706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBEP!MTB"
        threat_id = "2147895706"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 04 06 11 08 5d 13 0b 06 17 58 08 5d 13 0c 07 11 04 91 13 0d 20 00 01 00 00 13 05 11 0d 09 11 0b 91 61 07 11 0c 91 59 11 05 58 11 05 5d 13 0e 07 11 04 11 0e d2 9c 06 17 58 0a 06 08 11 07 17 58 5a fe 04 13 0f 11 0f 2d b3}  //weight: 1, accuracy: High
        $x_1_2 = "WeatherForecast_Client.Propertie" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBEQ_2147895820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBEQ!MTB"
        threat_id = "2147895820"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 06 11 04 5d 13 19 11 06 11 05 5d 13 1a 11 06 17 58 11 04 5d 13 1b 07 11 19 91 13 1c 20 00 01 00 00 13 1d 11 3f 20 ?? ?? ?? ?? 5a 20 ?? ?? ?? ?? 61}  //weight: 1, accuracy: Low
        $x_1_2 = "Event_Trace.Dangnhap.resource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AAWC_2147895853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AAWC!MTB"
        threat_id = "2147895853"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 08 07 8e 69 5d 02 07 08 07 8e 69 5d 91 11 04 08 11 04 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 28 ?? 00 00 0a d2 07 08 17 58 07 8e 69 5d 91 28 ?? 00 00 0a d2 59 20 00 01 00 00 58 28 ?? 00 00 06 28 ?? 00 00 0a d2 9c 08 15 58 0c 08 16 fe 04 16 fe 01 13 07 11 07 2d a8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AHND_2147896117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AHND!MTB"
        threat_id = "2147896117"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 09 07 8e 69 5d 07 09 07 8e 69 5d 91 08 09 1f 16 5d 91 61 28 ?? ?? ?? 0a 07 09 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "Deployment_Simulation" wide //weight: 1
        $x_1_3 = "Pi@s.Whit@" wide //weight: 1
        $x_1_4 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABON_2147896333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABON!MTB"
        threat_id = "2147896333"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 11 08 08 11 08 9a 1f 10 28 ?? 00 00 06 d2}  //weight: 2, accuracy: Low
        $x_2_2 = "SystemFileManager.IASIJHU.resources" ascii //weight: 2
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "Split" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABOP_2147896334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABOP!MTB"
        threat_id = "2147896334"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0c 07 08 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 1f 10 8d ?? ?? ?? 01 25 d0 ?? ?? ?? 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 0d 09 73 ?? ?? ?? 0a 13 04 11 04 07 6f ?? ?? ?? 0a 16 73 ?? ?? ?? 0a 13 05 09 8e 69 8d ?? ?? ?? 01 13 06 11 05 11 06 16 11 06 8e 69 6f ?? ?? ?? 0a 26 02 11 06}  //weight: 5, accuracy: Low
        $x_1_2 = "_007Stub.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABLD_2147896481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABLD!MTB"
        threat_id = "2147896481"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {43 69 6e 65 6d 61 4d 61 6e 61 67 65 72 2e 50 72 6f 70 65 72 74 69 65 73 00 72 65 73 6f 75 72 63 65}  //weight: 2, accuracy: High
        $x_2_2 = "CinemaManager.SellTicketForm" ascii //weight: 2
        $x_2_3 = "CinemaManager.PaymentForm" ascii //weight: 2
        $x_1_4 = "CinemaManager" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABLF_2147896482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABLF!MTB"
        threat_id = "2147896482"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 13 0b 11 0b 17 58 0d 09 20 ?? ?? ?? 00 5d 0d 11 05 11 09 09 94 58 13 05 11 05 20 ?? ?? ?? 00 5d 13 05 11 09 09 94 13 07 11 09 09 11 09 11 05 94 9e 11 09 11 05 11 07 9e 11 09 11 09 09 94 11 09 11 05 94 58 20 ?? ?? ?? 00 5d 94 13 06 11 0a 11 04 07 11 04 91 11 06 61 d2 9c 11 04 13 0b 11 0b 17 58 13 04 11 04 07 8e 69 32 94}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABHU_2147896501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABHU!MTB"
        threat_id = "2147896501"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {a2 25 17 20 ?? ?? ?? 14 28 ?? ?? ?? 06 a2 14 14 14 28 ?? ?? ?? 0a 14 20 ?? ?? ?? 14 28 ?? ?? ?? 06 18 8d ?? ?? ?? 01 25 16 20 ?? ?? ?? 14 28 ?? ?? ?? 06 a2 25 17 20 ?? ?? ?? 14 28 ?? ?? ?? 06 a2 14 14 14 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 07 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 0c 14}  //weight: 3, accuracy: Low
        $x_1_2 = "SorteoQuiniela.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABBA_2147896519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABBA!MTB"
        threat_id = "2147896519"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {07 06 08 06 8e 69 5d 91 02 08 91 61 d2 6f ?? ?? ?? 0a 08 17 58 0c 08 02 8e 69 3f ?? ?? ?? ff 07 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "InvokeMember" ascii //weight: 1
        $x_1_3 = "GetResponseStream" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABSG_2147896751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABSG!MTB"
        threat_id = "2147896751"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0c 08 07 6f ?? 00 00 0a 16 73 ?? 00 00 0a 0d 06 8e 69 8d ?? 00 00 01 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 26 11 04 28 ?? 00 00 06 26 73 ?? 00 00 06 17 6f ?? 00 00 06 de 14 09 2c 06 09 6f ?? 00 00 0a dc}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABXI_2147896754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABXI!MTB"
        threat_id = "2147896754"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 1c 1d 2d 0d 26 28 ?? 00 00 2b 28 ?? 00 00 2b 2b 03 26 2b f1 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "ReadAsByteArrayAsync" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AACR_2147896757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AACR!MTB"
        threat_id = "2147896757"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "TrafficSimulation.Properties.Resources" ascii //weight: 2
        $x_2_2 = "e591e7c5-3de9-4705-8ba5-5d3b04696147" ascii //weight: 2
        $x_1_3 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AAYS_2147898458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AAYS!MTB"
        threat_id = "2147898458"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 11 05 5d 13 06 06 11 07 5d 13 0a 07 11 06 91 13 0b 11 04 11 0a 6f ?? 00 00 0a 13 0c 02 07 06 28 ?? ?? 00 06 13 0d 02 11 0b 11 0c 11 0d 28 ?? ?? 00 06 13 0e 07 11 06 11 0e 20 00 01 00 00 5d d2 9c 06 17 59 0a 06 16 fe 04 16 fe 01 13 0f 11 0f 2d ad}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AAZG_2147898715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AAZG!MTB"
        threat_id = "2147898715"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 05 03 02 8e 69 6f ?? 00 00 0a 0a 2b 00 06 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "vsLhLhJBUCivwMwEUMTxEBAvTCUQJhvCDywZrpUfhf" wide //weight: 1
        $x_1_3 = "##C##r##e##a##t##e##I##n##s##t##a##n##c##e##" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_VR_2147899486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.VR!MTB"
        threat_id = "2147899486"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 00 01 00 00 13 0e 11 0d 17 58 13 0f 11 0d 11 06 5d 13 10 11 0f 11 06 5d 13 11 07 11 11 91 11 0e 58 13 12 07 11 10 91 13 13 11 05 11 0d 1f 16 5d 91 13 14 11 13 11 14 61 13 15 07 11 10 11 15 11 12 59 11 0e 5d d2 9c 00 11 0d 17 58 13 0d 11 0d 11 06 fe 04 13 16 11 16 2d a4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ARAC_2147899491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ARAC!MTB"
        threat_id = "2147899491"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 11 05 06 8e 69 5d 06 11 05 06 8e 69 5d 91 07 11 05 1f 16 5d 91 61 28 ?? ?? ?? 0a 06 11 05 17 58 06 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 05 15 58 13 05 11 05 16 fe 04 16 fe 01 13 06 11 06 2d b0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ARAD_2147899492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ARAD!MTB"
        threat_id = "2147899492"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 05 07 8e 69 5d 02 11 05 08 07 28 ?? ?? ?? 06 9c 00 11 05 15 58 13 05 11 05 16 fe 04 16 fe 01 13 06 11 06 2d d8}  //weight: 5, accuracy: Low
        $x_5_2 = {05 03 05 8e 69 5d 91 04 03 1f 16 5d 91 61 28 ?? ?? ?? 0a 05 03 17 58 05 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 0a 2b 00 06 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AAAP_2147899846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AAAP!MTB"
        threat_id = "2147899846"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 13 04 73 ?? ?? 00 0a 0b 14 fe ?? ?? 09 00 06 73 ?? 05 00 0a 28 ?? 09 00 06 28 ?? 0b 00 06 75 ?? 00 00 1b 73 ?? 05 00 0a 0c 08 11 04 16 73 ?? ?? 00 0a 0d 09 07 6f ?? 05 00 0a 7e ?? ?? 00 04 07 6f ?? ?? 00 0a 14 6f ?? ?? 00 0a de 15}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AIAA_2147900237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AIAA!MTB"
        threat_id = "2147900237"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 0d 16 13 04 2b 22 09 11 04 6f ?? 00 00 0a 13 05 07 08 11 05 06 08 06 8e 69 5d 91 59 d1 9d 08 17 58 0c 11 04 17 58 13 04 11 04 09 6f ?? 00 00 0a 32 d4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABF_2147900366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABF!MTB"
        threat_id = "2147900366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 13 07 2b 15 11 06 11 07 91 13 08 00 11 08 04 61 13 09 00 11 07 17 58 13 07 11 07 11 06 8e 69 32 e3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABF_2147900366_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABF!MTB"
        threat_id = "2147900366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 08 91 11 0a 61 13 0b 07 11 07 07 8e 69 5d 91 13 0c 11 0b 11 0c 20 00 01 00 00 58 59 13 0d 07 11 08 11 0d 20 00 01 00 00 5d d2 9c 11 06 17 58}  //weight: 2, accuracy: High
        $x_1_2 = "PhotoSorter" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABF_2147900366_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABF!MTB"
        threat_id = "2147900366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 07 2b 1c 00 06 11 07 11 07 1f 11 5a 11 07 18 62 61 20 aa 00 00 00 60 9e 00 11 07 17 58 13 07 11 07 06 8e 69 fe 04}  //weight: 2, accuracy: High
        $x_3_2 = {2b 18 11 06 11 09 11 05 11 09 19 5a 58 1f 18 5d 1f 0c 59 9e 11 09 17 58 13 09 11 09 11 06 8e 69 fe 04 13 0a 11 0a 2d da}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABF_2147900366_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABF!MTB"
        threat_id = "2147900366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 08 09 6f ?? 00 00 0a 13 05 07 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 17 13 04 2b a6 11 04 17 33 12 07 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 18 13 04 2b 8f 07 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 09 17 58 0d 16 13 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABF_2147900366_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABF!MTB"
        threat_id = "2147900366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0c 00 07 0e 04 6f ?? 00 00 0a 61 19 5f 17 fe 01 13 0a 11 0a 2c 09 00 08 07 1f 1f 5f 58 0c 00 00 de 08 00 08 1f 0a 61 0c}  //weight: 1, accuracy: Low
        $x_2_2 = {07 17 62 11 0b 19 58 61 0b 02 09 11 0b 6f ?? 00 00 0a 13 0c 04 03 6f ?? 00 00 0a 59 13 0d 11 0d 13 0f 11 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABF_2147900366_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABF!MTB"
        threat_id = "2147900366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 16 04 6f ?? 00 00 0a 9d 6f ?? 00 00 0a 17 fe 02 0a 06 2c 0a 00 04 17 6f ?? 00 00 0a 00 00 04 6f ?? 00 00 0a 1f 20 fe 01 0b 07 2c 0a 00 04 17 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {16 0d 2b 13 00 02 09 02 09 91 ?? ?? ?? ?? ?? 59 d2 9c 00 09 17 58 0d 09 02 8e 69 fe 04 13 04 11 04 2d e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABF_2147900366_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABF!MTB"
        threat_id = "2147900366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 06 07 6f ?? 00 00 0a 0c 04 03 6f ?? 00 00 0a 59 0d 09 19 fe 04 16 fe 01 13 04 11 04 2c 2f 00 03 19 8d ?? 00 00 01 25 16 12 02 28 ?? 00 00 0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 02 28 ?? 00 00 0a 9c 6f}  //weight: 3, accuracy: Low
        $x_2_2 = "IgniteFitnessTracker" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABF_2147900366_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABF!MTB"
        threat_id = "2147900366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5a 05 6c 5b 28 ?? 00 00 0a 02 7b ?? 01 00 04 5a 13 05 04 2c 11 11 04 04 8e 69 2f 0a 11 05 04 11 04 98 6c 5a 13 05 06 7b ?? 01 00 04 11 04 11 05 28 ?? 00 00 0a a1 11 04 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = {0a 0a 12 01 fe 15 ?? 00 00 02 12 01 12 00 28 ?? 01 00 0a 7d ?? 01 00 04 12 01 12 00 28 ?? 01 00 0a 7d ?? 01 00 04 12 01 12 00 28 ?? 01 00 0a 7d ?? 01 00 04 0e 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABF_2147900366_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABF!MTB"
        threat_id = "2147900366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {16 30 04 11 0f 2b 02 11 11 2b 02 11 10 13 0f 11 0f 6f ?? 00 00 0a 00 11 06 72 ?? 01 00 70 6f ?? 00 00 0a 07 5f 13 12 11 12 2c 0a 00 11 05 6f ?? 00 00 0a 00 00 00 11 0d 17}  //weight: 3, accuracy: Low
        $x_2_2 = {13 14 2b 15 12 14 28 ?? 00 00 0a 13 15 00 09 11 15 6f ?? 00 00 0a 61 0d 00 12 14 28}  //weight: 2, accuracy: Low
        $x_1_3 = "Assignment2_Winform" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABF_2147900366_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABF!MTB"
        threat_id = "2147900366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GUI_Services.CanBoGiaoVienGUI" ascii //weight: 1
        $x_1_2 = "GUI_Services.DanhSachGV1Lop" ascii //weight: 1
        $x_1_3 = "GUI_Services.DanhSachHocSinh" ascii //weight: 1
        $x_1_4 = "GUI_Services.PhanCongGiangDayGUI" ascii //weight: 1
        $x_1_5 = "GUI_Services.QuanLyHoSoHocSinh" ascii //weight: 1
        $x_1_6 = "GUI_Services.QuanLyLopGUI" ascii //weight: 1
        $x_1_7 = "GUI_Services.QuanLyMonHocGUI" ascii //weight: 1
        $x_1_8 = "GUI_Services.ThongTinGUI" ascii //weight: 1
        $x_1_9 = "HoSoHocSinhDTL" ascii //weight: 1
        $x_1_10 = "PhanCongGiangDayDTL" ascii //weight: 1
        $x_1_11 = "HoSoHocSinhBUS" ascii //weight: 1
        $x_1_12 = "40dbd603-575a-4370-b745-284fef7e1e51" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABO_2147900585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABO!MTB"
        threat_id = "2147900585"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 0a 16 0b 2b 0f 00 06 07 58 02 03 07 58 91 52 00 07 17 58 0b 07 05 fe 04 0c 08 2d e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABO_2147900585_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABO!MTB"
        threat_id = "2147900585"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 06 11 07 1b 5d 1f 1f 5f 63 05 11 07 19 5d 1f 1f 5f 62 61 61 0b 00 11 21}  //weight: 2, accuracy: High
        $x_1_2 = {06 19 62 0e 04 11 07 28 ?? 00 00 06 11 07 1f 11 5a 58 61 0a 11 21}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABO_2147900585_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABO!MTB"
        threat_id = "2147900585"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {16 0b 2b 36 06 07 28 ?? 00 00 06 16 0c 2b 15 07 08 28 ?? 00 00 06 02 07 08 03 04 28 ?? 00 00 06 08 17 58 0c 08 02 6f ?? 00 00 0a 2f 09 03 6f ?? 00 00 0a 04 32 d9}  //weight: 3, accuracy: Low
        $x_2_2 = {0a 02 03 04 6f ?? 00 00 0a 0e 04 05 6f ?? 00 00 0a 59 0b 06 28 ?? 00 00 06 07 05 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABO_2147900585_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABO!MTB"
        threat_id = "2147900585"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "8F6DD033256AAD8F49076E82A035F035F1FD03DFBAFCA9BF34F35F201052DB95" ascii //weight: 1
        $x_1_2 = "ConvertProvider.CommunicationForm" ascii //weight: 1
        $x_1_3 = "c3716158-e44d-41ea-a978-7b932944d640" ascii //weight: 1
        $x_1_4 = "ConvertProvider.ProtocolConfigForm" ascii //weight: 1
        $x_1_5 = "4OB54AK58F55F7R577RR84" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_BRAA_2147901204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.BRAA!MTB"
        threat_id = "2147901204"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 0c 2b 1b 00 07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a d2 9c 00 08 18 58 0c 08 06 fe 04 0d 09 2d dd}  //weight: 4, accuracy: Low
        $x_2_2 = "C6C646E2565627F63637D6" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ELAA_2147902956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ELAA!MTB"
        threat_id = "2147902956"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 25 26 28 ?? 00 00 0a 25 26 13 05}  //weight: 2, accuracy: Low
        $x_2_2 = {11 05 08 6f ?? 00 00 0a 25 26 11 07 20 00 01 00 00 14 14 11 06 74 ?? 00 00 1b 6f ?? 00 00 0a 25 26 26 2b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EWAA_2147903184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EWAA!MTB"
        threat_id = "2147903184"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 11 08 91 08 11 09 91 61 13 0b 11 0b 07 11 0a 91 59 20 00 01 00 00 58 20 00 01 00 00 5d 13 0c 07 11 08 11 0c d2 9c 11 05 17 58 13 05}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_FDAA_2147903191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.FDAA!MTB"
        threat_id = "2147903191"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 01 11 0a 11 10 11 13 5d d2 9c}  //weight: 1, accuracy: High
        $x_1_2 = {11 0c 11 0d 61 13 0f}  //weight: 1, accuracy: High
        $x_1_3 = {11 01 11 0b 91 11 13 58 13 0e}  //weight: 1, accuracy: High
        $x_1_4 = {11 07 1f 16 5d 91 13 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_FOAA_2147903396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.FOAA!MTB"
        threat_id = "2147903396"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 25 16 02 7b ?? 00 00 04 a2 25 17 02 7b ?? 00 00 04 a2 25 18 02 7b ?? 00 00 04 a2 25 19 02}  //weight: 1, accuracy: Low
        $x_1_2 = "y71r3SME5wfChP7ujEp+zVH" wide //weight: 1
        $x_1_3 = "UGXkZUmE" wide //weight: 1
        $x_1_4 = "LlJlZmxlY3Rpb24" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_SIO_2147905653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.SIO!MTB"
        threat_id = "2147905653"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://aideca.org.pe/mj/panel/uploads/Ggpaob.dat" ascii //weight: 1
        $x_1_2 = "Tnoqflwtlsa.jpeg" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_SIO_2147905653_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.SIO!MTB"
        threat_id = "2147905653"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetType" ascii //weight: 1
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "AwakeMethod" ascii //weight: 1
        $x_1_4 = "Invoke" ascii //weight: 1
        $x_1_5 = "://cdn.discordapp.com/attachments/1214453551124713515/1222028887492657262/Lndpmrcge.mp4" ascii //weight: 1
        $x_1_6 = "Smjhut.Consumers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_SYU_2147906366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.SYU!MTB"
        threat_id = "2147906366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 16 07 8e 69 20 00 10 00 00 1f 40 ?? ?? ?? ?? ?? 13 04 08 16 09 08 8e 69 ?? ?? ?? ?? ?? 07 16 11 04 07 8e 69 ?? ?? ?? ?? ?? 09 11 04 28 02 00 00 06 6f 0f 00 00 0a de 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {06 7e 01 00 00 04 72 01 00 00 70 6f 0c 00 00 0a 28 0d 00 00 0a 6f 08 00 00 06 0b 06 7e 01 00 00 04 72 2d 00 00 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NH_2147906970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NH!MTB"
        threat_id = "2147906970"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {59 d2 9c 06 17 58 0a 00 06 7e ?? 00 00 04 8e 69 fe 04 0b 07}  //weight: 7, accuracy: Low
        $x_1_2 = "TxtPassword" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "Elrmain\\obj\\Debug\\Elrmain.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ARAQ_2147908443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ARAQ!MTB"
        threat_id = "2147908443"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 1f 16 5d 91 61 07 08 17 58 09 5d 91 59 20 00 01 00 00 58 13 04 07 08 11 04 20 ff 00 00 00 5f 28 ?? ?? ?? 0a 9c 08 17 58 0c 08 07 8e 69 32 a0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RP_2147910353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RP!MTB"
        threat_id = "2147910353"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 7b 32 00 00 04 0f 01 28 47 00 00 0a 28 81 00 00 06 2a 00 13 30 05 00 1d 00 00 00 01 00 00 11 02 7b 38 00 00 04 16 02 7b 38 00 00 04 28 80 00 00 06 28 83 00 00 06 28 84 00 00 06 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_CZ_2147910479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.CZ!MTB"
        threat_id = "2147910479"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 07 17 73 ?? 00 00 0a 0d}  //weight: 2, accuracy: Low
        $x_2_2 = {09 02 16 02 8e 69 6f ?? 00 00 0a 00 09 6f}  //weight: 2, accuracy: Low
        $x_2_3 = {06 0b 07 06 8e 69 1f 40 12 02 28}  //weight: 2, accuracy: High
        $x_2_4 = {09 11 04 58 06 11 04 91 52}  //weight: 2, accuracy: High
        $x_2_5 = {11 04 17 58 13 04 11 04 06 8e 69 fe 04 13 05 11 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_CY_2147910480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.CY!MTB"
        threat_id = "2147910480"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 07 17 59 6f ?? 00 00 0a 08 8e 69 58 13 08 09 07 6f ?? 00 00 0a 11 08 59 13 09 11 09 8d ?? 00 00 01 13 04 06 11 08 11 04 16 11 09 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_CW_2147910482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.CW!MTB"
        threat_id = "2147910482"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 1f 0a 16 8d ?? 00 00 01 28 ?? 00 00 0a a5}  //weight: 2, accuracy: Low
        $x_1_2 = "VMEntry" ascii //weight: 1
        $x_1_3 = "KoiVM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_SG_2147911417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.SG!MTB"
        threat_id = "2147911417"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 51 00 00 04 7e 52 00 00 04 06 28 f8 00 00 06 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AMA_2147912163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AMA!MTB"
        threat_id = "2147912163"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 07 11 05 91 11 06 61 11 08 28 ?? 01 00 06 13 09 07 11 05 11 09 28 ?? 01 00 06 9c 11 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AMA_2147912163_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AMA!MTB"
        threat_id = "2147912163"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 59 0b 07 16 31 33 07 17 32 0d 03 12 00 28 ?? 00 00 0a 6f ?? 00 00 0a 07 18 32 0d 03 12 00 28 ?? 00 00 0a 6f ?? 00 00 0a 07 19 33 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AMO_2147912183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AMO!MTB"
        threat_id = "2147912183"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 08 91 09 61 07 08 17 58 07 8e 69 5d 91 13 04 11 04 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 05 07 08 11 05 28 ?? 00 00 0a 9c 08 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "EmployeeInfoApp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NJ_2147913583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NJ!MTB"
        threat_id = "2147913583"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5f 6a 61 d2 9c 00 11 0d 17 6a 58 13 0d 11 0d 11 07 8e 69 17 59}  //weight: 5, accuracy: High
        $x_1_2 = "tempuri.org/DataSet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NJ_2147913583_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NJ!MTB"
        threat_id = "2147913583"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 06 18 d8 1f 18 30 05 06 18 d8 2b 02 1f 18 0a 00 06 1f 18 5d 16 fe 01 0c 08 2c e4}  //weight: 5, accuracy: High
        $x_1_2 = "Password" ascii //weight: 1
        $x_1_3 = "CreditCardNumber" ascii //weight: 1
        $x_1_4 = "CreditCardCvv" ascii //weight: 1
        $x_1_5 = "BitcoinAddress" ascii //weight: 1
        $x_1_6 = "EthereumAddress" ascii //weight: 1
        $x_1_7 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AMK_2147913934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AMK!MTB"
        threat_id = "2147913934"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 13 06 2b 21 11 06 1c 5d 16 fe 01 13 07 11 07 2c 0d 06 11 06 06 11 06 91 1f 3d 61 b4 9c 00 00 11 06 17 d6 13 06 11 06 11 05 31 d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AMK_2147913934_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AMK!MTB"
        threat_id = "2147913934"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 05 1f 1f 5a 11 06 1f 11 5a 58 09 75 ?? ?? ?? 1b 8e 69 17 59 5f 13 08 1c 13 1a}  //weight: 2, accuracy: Low
        $x_1_2 = {11 0b 17 59 25 13 0b 16 fe 02 16 fe 01 13 17 18 13 1a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NQ_2147913961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NQ!MTB"
        threat_id = "2147913961"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {1f 16 5d 91 13 08 07 11 06 91 11 08 61 13 09 11 06 17 58 08 5d 13 0a 07 11 0a 91}  //weight: 10, accuracy: High
        $x_5_2 = {17 59 5f 13 0d 07 11 06 11 0d d2 9c 00 11 06 17 58 13 06 11 06}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NR_2147913962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NR!MTB"
        threat_id = "2147913962"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5f 6a 61 d2 9c 11 0a 17 6a 58 13 0a 11 0a 11 07 8e 69 17 59 6a 31 88}  //weight: 10, accuracy: High
        $x_5_2 = {5f d2 13 0c 11 06 11 0c 95 d2 13 0d 11 07 11 0a d4 11 0b 6e}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBYX_2147914000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBYX!MTB"
        threat_id = "2147914000"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {72 d6 01 00 70 72 da 01 00 70}  //weight: 5, accuracy: High
        $x_3_2 = "WindowsFormsApp2.Properties" ascii //weight: 3
        $x_2_3 = "60a8064f7d3f" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBYZ_2147914588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBYZ!MTB"
        threat_id = "2147914588"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {4c 00 6f 00 00 05 61 00 64 00 00 03 3f 00 00 03 42 00 00 03 3a 00 00 05 41 00 41}  //weight: 7, accuracy: High
        $x_1_2 = "Replace" ascii //weight: 1
        $x_1_3 = "Split" ascii //weight: 1
        $x_1_4 = "Grafik_Sistemi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ZQ_2147914979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ZQ!MTB"
        threat_id = "2147914979"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 c3 00 00 70 6f 5b 00 00 0a 13 0b 11 0b 11 08 1f 16 5d 91 13 0c 11 06 11 08 91 11 0c 61 13 0d 11 06 11 08 17 58 11 07 5d 91 13 0e 11 0d 11 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NKK_2147915264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NKK!MTB"
        threat_id = "2147915264"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5f 6a 61 d2 9c 00 11 10 17 58 13 10 11 10 11 08 17 59 fe 02 16}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_IJ_2147915368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.IJ!MTB"
        threat_id = "2147915368"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 59 22 00 70 6f ad 00 00 0a 13 07 11 07 09 1f 16 5d 91 13 08 07 09 91 11 08 61 13 09 09 18 58 17 59 08 5d 13 0a 07 11 0a 91 13 0b 11 09 11 0b 59 23 00 00 00 00 00 00 f0 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ASFQ_2147916507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ASFQ!MTB"
        threat_id = "2147916507"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {59 20 00 02 00 00 58 20 00 01 00 00 5d 20 00 04 00 00 58 20 00 02 00 00 5d 20 00 01 00 00 59 20 00 04 00 00 58 20 ff 00 00 00 5f}  //weight: 5, accuracy: High
        $x_2_2 = {20 00 01 00 00 14 14 17 8d ?? 00 00 01 25 16 08 a2 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NS_2147916584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NS!MTB"
        threat_id = "2147916584"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "7b8fc8ac-79a7-40db-a526-a68ceac91ada" ascii //weight: 5
        $x_1_2 = "UrlTokenDecode" ascii //weight: 1
        $x_1_3 = "get_Username" ascii //weight: 1
        $x_1_4 = "get_Password" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NNB_2147917313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NNB!MTB"
        threat_id = "2147917313"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 8e 69 1f 11 da 17 d6 ?? ?? 00 00 01 0d 02 16 09 16 02 8e 69 1f 10 da}  //weight: 2, accuracy: Low
        $x_2_2 = {0c 02 02 8e 69 1f 10 da 08 16 1f 10}  //weight: 2, accuracy: High
        $x_2_3 = {68 00 6f 00 6d 00 65 00 2f 00 70 00 78 00 6e 00 73 00 74 00 2f 00 75 00 73 00 65 00 72 00 73 00 2f 00 34 00 2f 00 53 00 74 00 75 00 62 00 2f 00 6f 00 62 00 6a 00 2f 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 2f 00 [0-32] 2e 00 70 00 64 00 62 00}  //weight: 2, accuracy: Low
        $x_2_4 = {68 6f 6d 65 2f 70 78 6e 73 74 2f 75 73 65 72 73 2f 34 2f 53 74 75 62 2f 6f 62 6a 2f 52 65 6c 65 61 73 65 2f [0-32] 2e 70 64 62}  //weight: 2, accuracy: Low
        $x_1_5 = "SHA256CryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_FormBook_CV_2147917423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.CV!MTB"
        threat_id = "2147917423"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 16 11 02 11 00 1a 28}  //weight: 2, accuracy: High
        $x_2_2 = {11 04 17 58 13 04}  //weight: 2, accuracy: High
        $x_2_3 = {11 07 5a 1a 5a 8d ?? 00 00 01 13 02}  //weight: 2, accuracy: Low
        $x_4_4 = {11 02 1a 11 03 16 11 03 8e 69 28}  //weight: 4, accuracy: High
        $x_2_5 = {11 02 16 28 ?? 00 00 06 8d ?? 00 00 01 13 03}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_CU_2147917437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.CU!MTB"
        threat_id = "2147917437"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {02 8e 69 17 59 91 1f ?? 61 18}  //weight: 4, accuracy: Low
        $x_2_2 = {02 8e 69 17 59 fe 02 16 fe 01}  //weight: 2, accuracy: High
        $x_2_3 = {61 06 09 91 16}  //weight: 2, accuracy: High
        $x_2_4 = {02 8e 69 17 58 8d}  //weight: 2, accuracy: High
        $x_2_5 = {02 8e 69 17 59 28}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NT_2147917724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NT!MTB"
        threat_id = "2147917724"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 00 00 5f d2 61 d2 81}  //weight: 5, accuracy: High
        $x_5_2 = "ca069172-b14a-40c4-b137-ac5721dad18c" ascii //weight: 5
        $x_1_3 = "C:\\temp\\NZESL.mdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NZC_2147917744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NZC!MTB"
        threat_id = "2147917744"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 03 04 05 5d 05 58 05 5d 91 0a 2b 00 06 2a}  //weight: 2, accuracy: High
        $x_2_2 = {00 03 04 03 8e 69 5d 03 8e 69 58 03 8e 69 5d 91 0a 2b 00 06 2a}  //weight: 2, accuracy: High
        $x_2_3 = {00 04 05 5d 05 58 05 5d 0a 03 06 91 0b}  //weight: 2, accuracy: High
        $x_1_4 = "GetGValue" ascii //weight: 1
        $x_1_5 = "xorByte" ascii //weight: 1
        $x_1_6 = "GetXorByte" ascii //weight: 1
        $x_1_7 = "CalculateKi" ascii //weight: 1
        $x_1_8 = "CalculateIntermediate3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ADG_2147918114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ADG!MTB"
        threat_id = "2147918114"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 13 0a 07 11 0a 91 13 0b 11 0b 11 07 61 11 09 59 20 00 02 00 00 58 13 0c 02 11 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NZE_2147920147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NZE!MTB"
        threat_id = "2147920147"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {14 16 9a 26 16 2d f9 02 03 02 4b 04 03 05 66 60 61 58 0e 07 0e 04 e0 95 58 7e ?? 00 00 04 0e 06 17 59 e0 95 58 0e 05 28 a7 00 00 06 58 54 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "0f172a7b-6240-4755-b3c4-7da71a2869f6" ascii //weight: 1
        $x_1_3 = "ToBase64String" ascii //weight: 1
        $x_1_4 = "CryptoConfig" ascii //weight: 1
        $x_1_5 = "Decrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NZF_2147920148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NZF!MTB"
        threat_id = "2147920148"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://91.92.254.178/saphire/Fjvsegjvlvf.vdf" ascii //weight: 3
        $x_1_2 = "ReadAsByteArrayAsync" ascii //weight: 1
        $x_1_3 = "GetAsync" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NZG_2147920149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NZG!MTB"
        threat_id = "2147920149"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {25 06 93 0b 06 18 58 93 07 61 0b}  //weight: 2, accuracy: High
        $x_2_2 = {11 0c 11 07 58 11 09 59 93 61 11 0b}  //weight: 2, accuracy: High
        $x_1_3 = "4838226c-11b7-46be-9677-81bbc9680cfd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NZG_2147920149_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NZG!MTB"
        threat_id = "2147920149"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "e2aa729e-6574-4bdf-a7a6-e0dbc808526b" ascii //weight: 3
        $x_1_2 = {00 03 4b 0a 03 04 4b 54 04 06 54}  //weight: 1, accuracy: High
        $x_1_3 = {91 11 07 11 10 95 61}  //weight: 1, accuracy: High
        $x_1_4 = "sendButton" ascii //weight: 1
        $x_1_5 = "PASSWORD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBXT_2147920461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBXT!MTB"
        threat_id = "2147920461"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 91 04 06 28 ?? 00 00 0a 05 6f ?? 00 00 0a 8e 69 5d 91 61 d2 9c 00 06 17 58 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBXT_2147920461_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBXT!MTB"
        threat_id = "2147920461"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "asdadsadsadsada" ascii //weight: 1
        $x_1_2 = "cccccccccc2123123" ascii //weight: 1
        $x_1_3 = "KoreanChess" wide //weight: 1
        $x_1_4 = "GetMethods" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBXT_2147920461_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBXT!MTB"
        threat_id = "2147920461"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 11 05 11 06 6f ?? 00 00 0a 13 07 08 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 00 08 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 00 08 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 00 07 08}  //weight: 3, accuracy: Low
        $x_2_2 = "Load" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBXT_2147920461_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBXT!MTB"
        threat_id = "2147920461"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "48FW7C48EFBH58C9ZF5714" wide //weight: 10
        $x_3_2 = "InvokeMember" ascii //weight: 3
        $x_2_3 = "GetObject" ascii //weight: 2
        $x_1_4 = "CreateInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_PNC_2147920784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.PNC!MTB"
        threat_id = "2147920784"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 07 17 58 20 ff 00 00 00 5f 13 07 11 05 11 04 11 07 95 58 20 ff 00 00 00 5f 13 05 11 04 11 07 95 13 06 11 04 11 07 11 04 11 05 95 9e 11 04 11 05 11 06 9e 11 04 11 07 95 11 04 11 05 95 58 20 ff 00 00 00 5f 13 13 11 04 11 13 95 d2 13 14 09 11 12 07 11 12 91 11 14 61 d2 9c 00 11 12 17 58 13 12 11 12 09 8e 69 fe 04 13 15 11 15 2d 90}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_OKZ_2147920796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.OKZ!MTB"
        threat_id = "2147920796"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 22 03 00 04 02 28 1f 07 00 06 13 05 7e 2d 03 00 04 11 04 11 05 16 11 05 8e 69 28 3a 07 00 06 13 06 7e 2e 03 00 04 7e ab 02 00 04 28 f3 06 00 06 11 06 28 3d 07 00 06 13 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_SMW_2147922411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.SMW!MTB"
        threat_id = "2147922411"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bitmap" ascii //weight: 1
        $x_1_2 = "TicTacToe" ascii //weight: 1
        $x_1_3 = "AppSistemaGaragem.Properties.Resources" ascii //weight: 1
        $x_1_4 = {00 02 0f 01 28 64 00 00 0a 6f 62 00 00 0a 00 02 0f 01 28 63 00 00 0a 6f 62 00 00 0a 19 0b 2b c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_SMI_2147922412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.SMI!MTB"
        threat_id = "2147922412"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$c20844fd-dd7c-4f38-a79c-09894ef20963" ascii //weight: 1
        $x_1_2 = "cmd.exe /c timeout 2 & start" ascii //weight: 1
        $x_1_3 = "ZT_RAT_Loader.Properties.Resources" ascii //weight: 1
        $x_1_4 = "Decrypt" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NZH_2147922728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NZH!MTB"
        threat_id = "2147922728"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "675282ac-a345-491b-9292-f1e54d17c1cc" ascii //weight: 3
        $x_1_2 = {00 06 07 72 3d 04 00 70 03 07 18 5a}  //weight: 1, accuracy: High
        $x_1_3 = {1a 62 72 3d 04 00 70 03 07 18 5a 17 58}  //weight: 1, accuracy: High
        $x_1_4 = "ContainsKey" ascii //weight: 1
        $x_1_5 = "CustomDecode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NZI_2147922729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NZI!MTB"
        threat_id = "2147922729"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {62 60 11 19 16 91 1e 62 60 11 19 17 91 1f 18 62 60 02 65 61}  //weight: 2, accuracy: High
        $x_1_2 = {61 11 1a 19 58 61 11 2f 61 d2 9c 17 11 09 58}  //weight: 1, accuracy: High
        $x_1_3 = {1d 5f 91 13 1c 11 1c 19 62 11 1c 1b 63 60 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBXU_2147922936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBXU!MTB"
        threat_id = "2147922936"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "4-2cb40949d72e" ascii //weight: 5
        $x_4_2 = "redist.exe" ascii //weight: 4
        $x_2_3 = "Redist.Background.png" ascii //weight: 2
        $x_1_4 = "$574c8cb7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBXU_2147922936_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBXU!MTB"
        threat_id = "2147922936"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 18 5d 2c ?? 02 06 07 6f ?? 00 00 0a 2b ?? 02 06 07 6f ?? 00 00 0a 0c 04 03 6f ?? 00 00 0a 59 0d 12 ?? 28 ?? 00 00 0a 13 ?? 12}  //weight: 2, accuracy: Low
        $x_1_2 = "Load" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBXU_2147922936_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBXU!MTB"
        threat_id = "2147922936"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 04 16 fe 01 13 09 11 09 2c 2b 00 72 0f 06 00 70}  //weight: 1, accuracy: High
        $x_2_2 = "rpgAssist.Properties.Resources.resource" ascii //weight: 2
        $x_3_3 = "TZINOU ANTONIA" wide //weight: 3
        $x_3_4 = {33 00 49 00 2d 00 54 00 45 00 50 00 30 00 31}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_BC_2147923053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.BC!MTB"
        threat_id = "2147923053"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 06 07 6f ?? 00 00 0a 0c 04 03 6f ?? 00 00 0a 59 0d 09 19 32 2c 03 19 8d ?? 00 00 01 25 16 12 02 28 ?? 00 00 0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 02 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 2b 33 09 16 31 2f 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 09 17 31 0d 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 09 18 31 0d 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 03 6f ?? 00 00 0a 04 32 01 2a 07 17 58 0b 07 02 6f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NZJ_2147923484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NZJ!MTB"
        threat_id = "2147923484"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 11 06 07 11 06 91 11 04 11 11 95 61 ?? ?? 00 00 0a 9c 11 06 17 58 13 06 00 11 06 6e 09 8e 69}  //weight: 2, accuracy: Low
        $x_1_2 = {11 04 11 09 95 11 04 11 07 95 58 20 ff 00 00 00 5f 13 11 11 06 19 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NZK_2147923485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NZK!MTB"
        threat_id = "2147923485"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 00 2b 4a 09 16 fe 02 13 05 11 05 2c 40 00 03 12 02}  //weight: 2, accuracy: High
        $x_1_2 = {59 0d 09 19 fe 04 16 fe 01 13 04 11 04 2c 2f 00 03 19}  //weight: 1, accuracy: High
        $x_1_3 = {04 fe 04 16 fe 01 13 08 11 08 2c 02 2b 2e 00 07 17 58 0b 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NZO_2147923486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NZO!MTB"
        threat_id = "2147923486"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 06 17 58 0a 06 02 6f ?? 00 00 0a fe 04 13 0b 11 0b}  //weight: 2, accuracy: Low
        $x_1_2 = {00 02 06 07 6f ?? 00 00 0a 0c 04 03 6f ?? 00 00 0a 59 0d 09 19 fe 04}  //weight: 1, accuracy: Low
        $x_1_3 = "6bebd5ac-a72c-44b8-a7d9-f01c2ae75635" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_SYI_2147923961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.SYI!MTB"
        threat_id = "2147923961"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 11 09 17 58 20 ff 00 00 00 5f 13 09 11 0a 11 06 11 09 95 58 20 ff 00 00 00 5f 13 0a 02 11 06 11 09 8f 69 00 00 01 11 06 11 0a 8f 69 00 00 01 28 16 00 00 06 00 11 06 11 09 95 11 06 11 0a 95 58 20 ff 00 00 00 5f 13 10 11 07 13 11 09 11 11 91 13 12 11 06 11 10 95 13 13 11 12 11 13 61 13 14 11 05 11 11 11 14 d2 9c 11 07 17 58 13 07 00 11 07 6e 11 05 8e 69 6a fe 04 13 15 11 15 2d 80}  //weight: 1, accuracy: High
        $x_1_2 = "V88G54KE8I58HT058BHQEA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NZM_2147924600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NZM!MTB"
        threat_id = "2147924600"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {26 16 02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58 7e ?? 00 00 04 0e 06 17 59 e0 95 58 0e 05 28 1b 00 00 06 58 54 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "2a4947de-7734-49a1-9fc0-945aa055af4b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NOC_2147925559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NOC!MTB"
        threat_id = "2147925559"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 03 16 61 04 16 60 ?? ?? 00 00 0a 0a 12 00 ?? ?? 00 00 0a 16 61}  //weight: 2, accuracy: Low
        $x_1_2 = {a2 08 17 58 0c 08 02 ?? ?? 00 00 06 8e 69 32 c6 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_BI_2147925677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.BI!MTB"
        threat_id = "2147925677"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 3d 04 16 fe 02 0c 08 2c 35 00 19 8d ?? 00 00 01 25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c 0d 02 09 04 28}  //weight: 2, accuracy: Low
        $x_2_2 = {04 19 fe 04 16 fe 01 0a 06 2c 53 00 0f 01 28 ?? 00 00 0a 1f 10 62 0f 01 28 ?? 00 00 0a 1e 62 60 0f 01 28 ?? 00 00 0a 60 0b 02 07 1f 10 63 20 ff 00 00 00 5f d2 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_BJ_2147925995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.BJ!MTB"
        threat_id = "2147925995"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {09 11 07 07 11 07 91 11 04 11 0d 95 61 d2 9c 11 0b 11 0e 5a 13 10 11 07 17 58 13}  //weight: 4, accuracy: High
        $x_1_2 = "DDZ45S4YWA57B9DV5GG57R" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_FormBook_NOD_2147926463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NOD!MTB"
        threat_id = "2147926463"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "db97782b-197a-4335-868a-51ae9ee87ebc" ascii //weight: 2
        $x_1_2 = "Ubix.BlackJack" ascii //weight: 1
        $x_1_3 = "ILogger" ascii //weight: 1
        $x_1_4 = "ConsoleLogger" ascii //weight: 1
        $x_1_5 = "SqlDbBackAndRestore" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AWDA_2147926625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AWDA!MTB"
        threat_id = "2147926625"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {09 11 0b 07 11 0b 91 11 04 11 0f 95 61 d2 9c 11 11 11 0d 5a 11 0b 58 20 00 01 00 00 5d 13 12 11 0c 11 12 61 13 0c 00 11 0b 17 58 13 0b 11 0b 07 8e 69 fe 04 13 15 11 15}  //weight: 4, accuracy: High
        $x_1_2 = "P848GOPEGY8Z4HEZ7C54CG" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBWB_2147926972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBWB!MTB"
        threat_id = "2147926972"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {62 4b 55 68 4a 53 57 63 57 50 51 64 50 53 61 62 53 00 4c 4c 4d 67 67 59 4b 64 64 4a 4e 4c 4c 62 4b 56 4d 00 66 65 4e 52 64 4e 58 59 61 65 61 56 61}  //weight: 2, accuracy: High
        $x_1_2 = "NReNLXeagVQdTNaeX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBWC_2147926973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBWC!MTB"
        threat_id = "2147926973"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 6f 61 62 41 67 72 65 65 38 65 6e 74 2e 65 78 65 00 6d 6f 61 62 32 79 65 00 6d 6f 61 62 37 79 65 00 6d 6f 61 62 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBWD_2147927278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBWD!MTB"
        threat_id = "2147927278"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 1f 09 91 1f 16 59 0b}  //weight: 2, accuracy: High
        $x_1_2 = "dfgfdfgd.Form1.resources" ascii //weight: 1
        $x_1_3 = "e30778f798a3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBWD_2147927278_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBWD!MTB"
        threat_id = "2147927278"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 04 11 04 11 05 6f ?? 00 00 06 11 04 09 6f 45 00 00 06 6f 22 00 00 06 02 7b 01 00 00 04 11 05 11 04}  //weight: 2, accuracy: Low
        $x_1_2 = "SkyrimCharacterParser.Properties" ascii //weight: 1
        $x_1_3 = "9ad5b201ae37" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ARM_2147928275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ARM!MTB"
        threat_id = "2147928275"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0c 16 13 06 2b 10 08 11 06 02 07 11 06 58 91 9c 11 06 17 58 13 06 11 06 08 8e 69 32 e9}  //weight: 3, accuracy: High
        $x_2_2 = {0a 16 0d 2b 44 17 13 04 16 13 05 2b 1f 02 09 11 05 58 91 72 01 00 00 70 11 05 28 ?? 00 00 0a 2e 05 16 13 04 2b 14 11 05 17 58}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AUGA_2147928634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AUGA!MTB"
        threat_id = "2147928634"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {01 25 16 11 0b 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 0b 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 0b 20 ff 00 00 00 5f d2 9c}  //weight: 3, accuracy: High
        $x_2_2 = {01 25 16 12 06 28 ?? 00 00 0a 9c 25 17 12 06 28 ?? 00 00 0a 9c 25 18 12 06 28 ?? 00 00 0a 9c 11 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ACHA_2147928928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ACHA!MTB"
        threat_id = "2147928928"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0d 09 07 6f ?? 00 00 0a 00 09 18 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 13 04 11 04 03 16 03 8e 69 6f ?? 00 00 0a 13 05 09}  //weight: 4, accuracy: Low
        $x_2_2 = "daoL" wide //weight: 2
        $x_2_3 = "SudokuPuzzle" wide //weight: 2
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_PLHH_2147928934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.PLHH!MTB"
        threat_id = "2147928934"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 13 04 11 04 20 ?? 4b 00 00 28 ?? 03 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 20 ?? 4a 00 00 28 ?? 03 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 0a de 0c}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NAH_2147929250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NAH!MTB"
        threat_id = "2147929250"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "https://files.catbox.moe/" ascii //weight: 2
        $x_1_2 = "Injection successful" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "HttpWebRequest" ascii //weight: 1
        $x_1_5 = "FREAKY.RunPE" ascii //weight: 1
        $x_1_6 = "SecurityProtocolType" ascii //weight: 1
        $x_1_7 = "BLAST" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ARHA_2147929311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ARHA!MTB"
        threat_id = "2147929311"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {01 25 16 11 0c 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 0c 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 0c 20 ff 00 00 00 5f d2 9c}  //weight: 3, accuracy: High
        $x_2_2 = {01 25 16 12 07 28 ?? 00 00 0a 9c 25 17 12 07 28 ?? 00 00 0a 9c 25 18 12 07 28 ?? 00 00 0a 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ASD_2147929952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ASD!MTB"
        threat_id = "2147929952"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 44 00 00 0a 13 26 12 26 28 45 00 00 0a 11 0b 5a 73 46 00 00 0a 11 0e 6f 47 00 00 0a 00 02 09 11 0b 11 0d 2d 08 11 0e 16 91 17 5d 2b 01 16 58 28 0c 00 00 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_GKN_2147930692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.GKN!MTB"
        threat_id = "2147930692"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 28 03 00 00 2b 73 8d 00 00 0a a2 25 17 72 d5 02 00 70 a2 25 18 72 e3 02 00 70 a2 0c d0 6f 00 00 01 28 85 00 00 0a 72 ff 02 00 70 20 00 01 00 00 14 14 18 8d 10 00 00 01 25}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBWO_2147930893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBWO!MTB"
        threat_id = "2147930893"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 07 1f 10 5d 04 07 d8 b5 9d 02 03 04 07 05 28 ?? 00 00 06 07 17 d6 0b}  //weight: 3, accuracy: Low
        $x_2_2 = {06 17 07 1e 5d 1f 1f 5f 62 60 0a 02 03 07 91}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RVA_2147931571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RVA!MTB"
        threat_id = "2147931571"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 95 a2 29 09 0b 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 91 00 00 00 09 00 00 00 25 00 00 00 41 00 00 00 3e 00 00 00 fb 00 00 00 17 00 00 00 01 00 00 00 27 00 00 00 03 00 00 00 0b 00 00 00 0c 00 00 00 0c 00 00 00 01 00 00 00 01 00 00 00 07 00 00 00 04 00 00 00 01 00 00 00 04}  //weight: 1, accuracy: High
        $x_1_2 = {57 95 a2 29 09 1e 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 a9 00 00 00 10 00 00 00 31 00 00 00 b6 00 00 00 3e 00 00 00 11 01 00 00 8a 00 00 00 05 00 00 00 52 00 00 00 03 00 00 00 0b 00 00 00 0c 00 00 00 18 00 00 00 05 00 00 00 01 00 00 00 07 00 00 00 06 00 00 00 81 00 00 00 63}  //weight: 1, accuracy: High
        $x_2_3 = "17b60f4c-8a91-4715-8d2c-303f7b8700fe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_FormBook_RVC_2147932500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RVC!MTB"
        threat_id = "2147932500"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 95 a2 29 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 9b 00 00 00 2a 00 00 00 2c 01 00 00 2b 01 00 00 8f 01 00 00 48 01 00 00 63 00 00 00 01 00 00 00 5d 00 00 00 07 00 00 00 17 00 00 00 2b 00 00 00 1b 00 00 00 01 00 00 00 01 00 00 00 07 00 00 00 16 00 00 00 01 00 00 00 01 00 00 00 03}  //weight: 1, accuracy: High
        $x_1_2 = "7ee282ab-b519-4615-9504-bdff0be83247" ascii //weight: 1
        $x_1_3 = "Polyclinic" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_PLJFH_2147932503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.PLJFH!MTB"
        threat_id = "2147932503"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {01 25 16 02 ?? 00 00 ff 00 5f 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 02 20 ?? ff 00 00 5f 1e 63 20 ff 00 00 00 5f d2 9c 25 18 02 20 ff 00 00 00 5f 20 ff 00 00 00 5f d2 9c 13 05 2b 00 11 05 2a}  //weight: 6, accuracy: Low
        $x_5_2 = {0a 1f 10 62 0f 00 28 ?? 00 00 0a 1e 62 60 0f 00 28 ?? 00 00 0a 60 0b 2b 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NFC_2147933366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NFC!MTB"
        threat_id = "2147933366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 17 58 0a 03 25 5a 0c 03 08 58 0c}  //weight: 2, accuracy: High
        $x_1_2 = "6de5d9ec-6984-4d53-b074-14190a66b00f" ascii //weight: 1
        $x_1_3 = {cc 05 04 61 ?? ?? 59 06 61 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AAD_2147933776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AAD!MTB"
        threat_id = "2147933776"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4D5A9~03~~04~~FFFF~0B8~~~~004~~~~~~~~~~~~~~~~~~~~~~~008~~00E1FBA0E0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_BAA_2147934276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.BAA!MTB"
        threat_id = "2147934276"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {06 08 6f 47 02 00 0a 26 04 07 08 91 6f 48 02 00 0a 08 17 58 0c 08 03 32 e7}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_BAA_2147934276_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.BAA!MTB"
        threat_id = "2147934276"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 28 07 00 00 06 0a 73 0a 00 00 0a 25 06 28 05 00 00 06 6f 0b 00 00 0a 0b dd 08}  //weight: 1, accuracy: High
        $x_1_2 = {02 03 1f 1f 5f 63 02 1e 03 59 1f 1f 5f 62 60 d2 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RVD_2147934285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RVD!MTB"
        threat_id = "2147934285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 9d a2 3d 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 b4 00 00 00 27 00 00 00 c3 00 00 00 a4 00 00 00 c0 00 00 00 93 01 00 00 3b 00 00 00 39 00 00 00 01 00 00 00 43 00 00 00 02 00 00 00 04 00 00 00 05 00 00 00 05 00 00 00 06 00 00 00 11 00 00 00 01 00 00 00 01 00 00 00 08 00 00 00 05 00 00 00 10 00 00 00 02}  //weight: 1, accuracy: High
        $x_1_2 = "6501818c-957a-4a60-a887-5e7fde2da52a" ascii //weight: 1
        $x_1_3 = "WindowsFormsOCR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AKB_2147934595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AKB!MTB"
        threat_id = "2147934595"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 06 11 07 1b 5d 1f 1f 5f 63 05 11 07 19 5d 1f 1f 5f 62 61 61 0b 11 21}  //weight: 2, accuracy: High
        $x_1_2 = {07 06 61 1f 18 5f 1f 10 fe 01 2b 01 16 13 09 11 09 2d 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AKB_2147934595_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AKB!MTB"
        threat_id = "2147934595"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 27 00 07 11 1d 11 1e 11 24 94 1f 1f 5f 63 20 ff 00 00 00 5f d2 6f ?? ?? ?? 0a 00 00 11 24 17 58 13 24 11 1f 17 59 13 1f 11 24 19 2f 07 11 1f 16 fe 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AKB_2147934595_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AKB!MTB"
        threat_id = "2147934595"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {9c 0b 16 0c 2b 1f 07 08 91 1f 7f 26 26 04 07 08 91 6f ?? 00 00 0a 06 08 06 08 94 18 5a 1f 64 5d 9e 08 17 58 0c 08 03 32 dd}  //weight: 3, accuracy: Low
        $x_1_2 = {5a 0a 06 17 28 ?? 00 00 0a 0a 03 19 8d ?? 00 00 01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28}  //weight: 1, accuracy: Low
        $x_2_3 = "AbdullahHassanAbdo_Lab5" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RVE_2147934687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RVE!MTB"
        threat_id = "2147934687"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 3f b6 1d 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 ba 00 00 00 40 00 00 00 7d 01 00 00 e5 02 00 00 7d 02 00 00 11 00 00 00 f4 01 00 00 21 00 00 00 d5 02 00 00 01 00 00 00 50 00 00 00 10 00 00 00 3a 00 00 00 24 00 00 00 94 00 00 00 90 01 00 00 03 00 00 00 10 00 00 00 08 00 00 00 01 00 00 00 08 00 00 00 03 00 00 00 07 00 00 00 0d}  //weight: 1, accuracy: High
        $x_1_2 = "71083a9b-c09e-430e-b2be-1f5d132290c0" ascii //weight: 1
        $x_1_3 = "Minimal.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RVF_2147935381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RVF!MTB"
        threat_id = "2147935381"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 15 a2 09 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 89 00 00 00 0f 00 00 00 b9 00 00 00 71 00 00 00 9e 00 00 00 f7 00 00 00 18 00 00 00 18 00 00 00 02 00 00 00 04 00 00 00 05 00 00 00 0b 00 00 00 01 00 00 00 07 00 00 00 0a 00 00 00 02 00 00 00 11}  //weight: 1, accuracy: High
        $x_1_2 = "c8ba41e7-0651-4488-b16f-f6e797b3ffe8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RVG_2147935758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RVG!MTB"
        threat_id = "2147935758"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 17 b6 09 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 88 00 00 00 13 00 00 00 6f 00 00 00 78 00 00 00 75 00 00 00 02 00 00 00 eb 00 00 00 53 00 00 00 2c 00 00 00 02 00 00 00 02 00 00 00 05 00 00 00 11 00 00 00 23 00 00 00 10 00 00 00 01 00 00 00 06 00 00 00 05 00 00 00 01 00 00 00 05}  //weight: 1, accuracy: High
        $x_1_2 = "94a1ee76-90fa-4258-b851-a8e4ea48d5dc" ascii //weight: 1
        $x_1_3 = "AdminDB.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RVH_2147936513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RVH!MTB"
        threat_id = "2147936513"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 15 a2 09 09 09 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 6d 00 00 00 0d 00 00 00 39 00 00 00 46 00 00 00 4e 00 00 00 b2 00 00 00 26 00 00 00 19 00 00 00 04 00 00 00 08 00 00 00 0d 00 00 00 06 00 00 00 01 00 00 00 05 00 00 00 05 00 00 00 02}  //weight: 2, accuracy: High
        $x_1_2 = "76aa32d9-be9d-4da2-9400-03dff05bd172" ascii //weight: 1
        $x_1_3 = "MathLab_Core" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RVH_2147936513_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RVH!MTB"
        threat_id = "2147936513"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 17 a2 0b 09 05 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 55 00 00 00 1d 00 00 00 25 00 00 00 80 00 00 00 66 00 00 00 0a 00 00 00 8e 00 00 00 47 00 00 00 19 00 00 00 06 00 00 00 10 00 00 00 1d 00 00 00 02 00 00 00 04 00 00 00 01 00 00 00 06 00 00 00 02 00 00 00 01}  //weight: 1, accuracy: High
        $x_1_2 = "37b62967-05c4-46a1-a333-c314da2055cb" ascii //weight: 1
        $x_1_3 = "ChinhDo.Transactions.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RVI_2147936986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RVI!MTB"
        threat_id = "2147936986"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 d5 a2 29 09 1e 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 ?? 00 00 00 1b 00 00 00 48 00 00 00 cc 00 00 00 36 00 00 00 01 01 00 00 ?? 00 00 00 01 00 00 00 04 00 00 00 ?? 00 00 00 07 00 00 00 1f 00 00 00 31 00 00 00 22 00 00 00 04 00 00 00 01 00 00 00 06 00 00 00 0b 00 00 00 76 00 00 00 59}  //weight: 1, accuracy: Low
        $x_1_2 = {57 d5 a2 29 09 1e 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 a8 00 00 00 19 00 00 00 46 00 00 00 c8 00 00 00 36 00 00 00 01 01 00 00 bd 00 00 00 01 00 00 00 04 00 00 00 5c 00 00 00 07 00 00 00 1f 00 00 00 31 00 00 00 22 00 00 00 04 00 00 00 01 00 00 00 07 00 00 00 09 00 00 00 76 00 00 00 59}  //weight: 1, accuracy: High
        $x_2_3 = "4377972A-EA86-47FE-8BF0-03C541BA855D" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_FormBook_NME_2147937062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NME!MTB"
        threat_id = "2147937062"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4377972A-EA86-47FE-8BF0-03C541BA855D" ascii //weight: 1
        $x_2_2 = {11 0c 11 07 58 11 09 59 93 61 11 0b}  //weight: 2, accuracy: High
        $x_1_3 = {25 06 93 0b 06 18 58 93 07 61 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RVJ_2147937076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RVJ!MTB"
        threat_id = "2147937076"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 15 a2 09 09 09 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 89 00 00 00 0c 00 00 00 3f 00 00 00 53 00 00 00 52 00 00 00 ec 00 00 00 36 00 00 00 21 00 00 00 05 00 00 00 14 00 00 00 1d 00 00 00 08 00 00 00 01 00 00 00 07 00 00 00 07 00 00 00 02}  //weight: 1, accuracy: High
        $x_1_2 = "27c475ba-6a0e-4356-b128-e6bf0bfaa4bb" ascii //weight: 1
        $x_1_3 = "Marksheet_Project" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NMF_2147937089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NMF!MTB"
        threat_id = "2147937089"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "2a51d621-3e0d-4293-a2ad-964721bfff7b" ascii //weight: 2
        $x_1_2 = {25 4a 09 61 54 09 17 62 09 1d 63 60 0d 11 06 17 58}  //weight: 1, accuracy: High
        $x_1_3 = {1b 62 11 04 19 63 60 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NMG_2147937145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NMG!MTB"
        threat_id = "2147937145"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "2a51d621-3e0d-4293-a2ad-964721bfff7b" ascii //weight: 2
        $x_1_2 = "b03f5f7f11d50a3ahSystem" ascii //weight: 1
        $x_1_3 = "OnKeyDown" ascii //weight: 1
        $x_1_4 = "keyEventArgs" ascii //weight: 1
        $x_1_5 = "NodesControl_MouseMove" ascii //weight: 1
        $x_1_6 = "add_MouseClick" ascii //weight: 1
        $x_1_7 = "Mariusz Komorowski" ascii //weight: 1
        $x_1_8 = "b77a5c561934e089#System" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ZHU_2147937871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ZHU!MTB"
        threat_id = "2147937871"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {16 61 d2 9c 25 17 0f 00 28 ?? ?? ?? ?? 16 60 d2 9c 25 18 0f 00 28 ?? ?? ?? ?? 20 ff 00 00 00 5f d2 9c}  //weight: 6, accuracy: Low
        $x_5_2 = {13 04 04 19 8d ?? 00 00 01 25 16 08 9c 25 17 09 9c 25 18 11 04 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MJT_2147938548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MJT!MTB"
        threat_id = "2147938548"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 00 72 61 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 20 01 00 00 00 7e 91 02 00 04 7b 7b 02 00 04 3a 0f 00 00 00 26 20 00 00 00 00 38 04 00 00 00 fe 0c 04 00}  //weight: 4, accuracy: Low
        $x_5_2 = {38 30 00 00 00 11 00 72 93 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 20 00 00 00 00 7e 91 02 00 04 7b a8 02 00 04 3a c5 ff ff ff 26 20 00 00 00 00 38 ba ff ff ff 11 00 6f ?? 00 00 0a 03 16 03 8e 69 6f ?? 00 00 0a 13 02 20 02 00 00 00 38 9d ff ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_BAB_2147938613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.BAB!MTB"
        threat_id = "2147938613"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 07 11 07 07 11 07 94 03 5a 1f 64 5d 9e 00 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 2d de}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_LAT_2147938652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.LAT!MTB"
        threat_id = "2147938652"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 02 11 04 11 05 6f ?? 00 00 0a 13 06 04 03 6f ?? 00 00 0a 59 13 07 11 07 19 fe 04 16 fe 01 13 08 11 08 2c 2e 00 03 12 06 28 ?? 00 00 0a 6f 89 00 00 0a 00 03 12 06 28 8a 00 00 0a 6f ?? 00 00 0a 00 03 12 06 28 8b 00 00 0a 6f 89 00 00 0a 00 00 2b 58 11 07 16 fe 02 13 09 11 09 2c 4d 00 19 8d 4f 00 00 01 25 16 12 06 28 ?? 00 00 0a 9c 25 17 12 06 28 8a 00 00 0a 9c 25 18 12 06 28 8b 00 00 0a 9c 13 0a 16 13 0b 2b 14}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AKO_2147938938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AKO!MTB"
        threat_id = "2147938938"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 15 12 15 28 ?? 00 00 0a 16 61 d2 13 16 12 15 28 ?? 00 00 0a 16 61 d2 13 17 12 15 28 ?? 00 00 0a 16 61 d2 13 18 19 8d ?? 00 00 01 25 16 11 16}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AKO_2147938938_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AKO!MTB"
        threat_id = "2147938938"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 fe 01 13 0b 11 0b 2c 5a 00 03 19 8d ?? 00 00 01 25 16 12 07 28 ?? 00 00 0a 9c 25 17 12 07 28 ?? 00 00 0a 9c 25 18 12 07 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 28 ?? 00 00 0a 13 0d 12 0d 28 ?? 00 00 0a 18 5d 17 fe 01 13 0c 11 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AKO_2147938938_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AKO!MTB"
        threat_id = "2147938938"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 08 09 6f ?? 01 00 0a 13 04 04 03 6f ?? 01 00 0a 59 13 05 11 05 19 32 29 03 12 04 28 ?? 01 00 0a 6f ?? 01 00 0a 03 12 04 28 ?? 01 00 0a 6f ?? 01 00 0a 03 12 04 28 ?? 01 00 0a 6f ?? 01 00 0a 2b 47 11 05 16 31 42 19 8d ?? 00 00 01 25 16 12 04 28 ?? 01 00 0a 9c 25 17 12 04 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_WST_2147938981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.WST!MTB"
        threat_id = "2147938981"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 05 07 11 05 94 02 5a 1f 64 5d 9e 11 0a 20 ?? 80 37 a9 5a 20 b1 df 46 f9 61 38 ?? fe ff ff 16 13 05 11 0a 20 0c 52 4f b1 5a 20 53 2e 79 70 61 38 3c fe ff ff 16 0c 11 0a 20 f8 95 3c 22 5a 20 81 c5 06 04 61 38 27 fe ff ff 11 07 07 8e 69 fe 04 13 08 11 08 2d 08 20 62 9f a8 93 25 2b 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_TRT_2147939164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.TRT!MTB"
        threat_id = "2147939164"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 0d 11 0d 06 7d 47 03 00 04 00 11 0d 02 11 0a 11 0c 6f ?? 00 00 0a 7d 45 03 00 04 11 0d 04 11 0d 7b 47 03 00 04 7b 44 03 00 04 6f ?? 00 00 0a 59 7d 46 03 00 04 7e 49 03 00 04 25 2d 17 26 7e 48 03 00 04 fe 06 82 02 00 06 73 86 00 00 0a 25 80 49 03 00 04 13 0e 11 0d fe 06 7e 02 00 06 73 86 00 00 0a 13 0f 11 0d fe 06 7f 02 00 06 73 86 00 00 0a 13 10 11 0d 7b 46 03 00 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_YRT_2147939188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.YRT!MTB"
        threat_id = "2147939188"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 00 72 61 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 20 03 00 00 00 fe 0e 04 00 38 00 00 00 00 fe 0c 04 00 45 04 00 00 00 2d 00 00 00 83 00 00 00 05 00 00 00 53 00 00 00 38 28 00 00 00 11 00 6f ?? 00 00 0a 13 01 20 00 00 00 00 7e 96 00 00 04 7b 62 00 00 04 3a c9 ff ff ff 26 20 00 00 00 00 38 be ff ff ff 73 16 00 00 0a 13 09 20 01 00 00 00 7e 96 00 00 04 7b 53 00 00 04 3a a3 ff ff ff 26 20 00 00 00 00 38 98 ff ff ff 11 00 72 93 00 00 70 28 13 00 00 0a 6f 17 00 00 0a 20 01 00 00 00 7e 96 00 00 04 7b 88 00 00 04 3a 73 ff ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_PDD_2147939349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.PDD!MTB"
        threat_id = "2147939349"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1a 25 2c 17 8d 5b 00 00 01 0b 06 07 16 1a 6f ?? 00 00 0a 26 07 16 28 ?? 01 00 0a 0c 06 16 73 13 01 00 0a 0d 2b 36 8d 5b 00 00 01 2b 32 16 2b 33 2b 1c 2b 33 2b 34 2b 36 08 11 05 59 6f ?? 00 00 0a 13 06 11 06 2c 0c 11 05 11 06 58 13 05 11 05 08 32 df 1b 2c ed 11 04 13 07 de 36 08 2b c7 13 04 2b ca 13 05 2b c9 09 2b ca 11 04 2b c8 11 05 2b c6}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_PGT_2147939426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.PGT!MTB"
        threat_id = "2147939426"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 0c 02 11 0c 7b 98 00 00 04 7b 94 00 00 04 11 0c 7b 98 00 00 04 7b 94 00 00 04 60 11 0c 7b 98 00 00 04 7b 94 00 00 04 5f 11 0b 11 0b 60 11 0b 5f 6f ?? 00 00 0a 7d 96 00 00 04 11 0c 04 11 0c 7b 98 00 00 04 7b 95 00 00 04 7b 93 00 00 04 6f ?? 00 00 0a 59 7d 97 00 00 04 7e ?? 00 00 04 25 2d 17}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_VGG_2147939712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.VGG!MTB"
        threat_id = "2147939712"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 da 26 00 00 28 ?? 02 00 06 28 ?? 00 00 0a 0a 20 95 23 00 00 28 92 02 00 06 28 0f 00 00 0a 0b 73 10 00 00 0a 0c 73 11 00 00 0a 0d 09 08 06 07 6f 12 00 00 0a 17 73 13 00 00 0a 13 04 11 04 03 16 03 8e 69 6f 14 00 00 0a 09 6f ?? 00 00 0a 13 05 de 20}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_VNT_2147939797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.VNT!MTB"
        threat_id = "2147939797"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 11 07 11 09 6f ?? 00 00 0a 13 0a 11 06 11 05 6f ?? 00 00 0a 59 13 0b 11 0b 19 32 3d 19 8d 63 00 00 01 25 16 12 0a 28 ?? 00 00 0a 9c 25 17 12 0a 28 ?? 00 00 0a 9c 25 18 12 0a 28 ?? 00 00 0a 9c 13 0c 08 72 9b 0f 00 70 28 ?? 00 00 0a 26 11 05 11 0c ?? ?? 00 00 0a 2b 48 11 0b 16 31 43 19 8d 63 00 00 01 25 16 12 0a 28 8d 00 00 0a 9c 25 17 12 0a 28 8e 00 00 0a 9c 25 18 12 0a 28 8f 00 00 0a 9c 13 0d 16 13 0e 2b 12}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ABSA_2147939974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ABSA!MTB"
        threat_id = "2147939974"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 11 07 11 0b 6f ?? ?? 00 0a 13 0c 11 17 20 9f 26 26 22 5a 20 47 37 da 6c 61 38 ?? fe ff ff 00 11 17 20 e1 e3 ce bd 5a 20 f7 7d 31 c4 61 38 ?? fe ff ff 00 11 17 20 14 cf aa 52 5a 20 1f 4d 73 aa 61 38 ?? fe ff ff 11 06 11 05 6f ?? ?? 00 0a 59 13 0d 11 0d 19 fe 04 16 fe 01 13 0e 11 0e 2d 08}  //weight: 5, accuracy: Low
        $x_2_2 = {01 25 16 12 0c 28 ?? ?? 00 0a 9c 25 17 12 0c 28 ?? ?? 00 0a 9c 25 18 12 0c 28 ?? ?? 00 0a 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_VTB_2147940204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.VTB!MTB"
        threat_id = "2147940204"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 06 11 04 6f ?? 01 00 0a 13 14 09 07 6f ?? 00 00 0a 59 13 06 11 06 19 fe 04 16 fe 01 13 0c 11 0c 2c 54 19 8d 0b 00 00 01 25 16 12 14 28 ?? 01 00 0a 9c 25 17 12 14 28 ?? 01 00 0a 9c 25 18 12 14 28 ?? 01 00 0a 9c 13 0d 11 09 20 7e a3 55 48 28 ?? 00 00 06 28 ?? 01 00 0a 2c 03}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_WGB_2147940327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.WGB!MTB"
        threat_id = "2147940327"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 07 08 6f ?? 00 00 0a 0d 04 03 6f ?? 00 00 0a 59 13 04 11 04 19 fe 04 16 fe 01 13 05 11 05 2c 2e 00 03 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_4_2 = {25 16 12 03 28 ?? 00 00 0a 9c 25 17 12 03 28 9e 00 00 0a 9c 25 18 12 03 28 ?? 00 00 0a 9c 13 07 16 13 08}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_IGB_2147940381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.IGB!MTB"
        threat_id = "2147940381"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 07 08 6f ?? 00 00 0a 0d 04 03 6f ?? 00 00 0a 59 13 04 11 04 19 fe 04 16 fe 01 13 05 11 05 2c 2e 00 03 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 2b 58}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NAV_2147940774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NAV!MTB"
        threat_id = "2147940774"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "9c950443-1b8d-4602-a3ee-6634b3d256af" ascii //weight: 2
        $x_1_2 = {c3 f1 5e e0 06 8d 72 55 a2 5e d9 84 cb 62 02 84 99 d3 7d 32 23 01 44 44 10 65 c7 b6 fe 33 89 4f}  //weight: 1, accuracy: High
        $x_1_3 = {80 cc cc 59 ba cf d7 cb f7 3e cf fb 24 2c 99 74 57 fd 7f 75 55 77 2d 03 06 10 42 08 21 84 10 42 08 21 84 10 42 08 89 1f 1d cb 66 6d e6 15 b2 e3 3d 27 7b b0 9b 53 c7 bb 8e fe b6 e7 a8 2b 3c a3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AKN_2147940889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AKN!MTB"
        threat_id = "2147940889"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 08 11 04 6f ?? 00 00 0a 13 09 19 8d ?? 00 00 01 25 16 12 09 28 ?? 00 00 0a 6c 07 16 9a 16 99 5a a1 25 17 12 09 28 ?? 00 00 0a 6c 07 17 9a 17 99 5a a1 25 18 12 09 28 ?? 00 00 0a 6c 07 18 9a 18 99 5a a1}  //weight: 2, accuracy: Low
        $x_1_2 = "CalculadoraMediaAluno" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MBZ_2147941160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MBZ!MTB"
        threat_id = "2147941160"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "EtecNews.Properties.Resources.resourc" ascii //weight: 4
        $x_6_2 = {74 00 65 00 63 00 4e 00 65 00 77 00 73 00 00 1d 43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_BSA_2147942406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.BSA!MTB"
        threat_id = "2147942406"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 6c 61 72 6d 00 41 6c 61 72 6d 65 72 00 4f 62 6a 65 63 74 00 3c 52 75 6e}  //weight: 2, accuracy: High
        $x_4_2 = "dc83410f-364e-4413-bbdf-3148fef27842" ascii //weight: 4
        $x_8_3 = "sVca.exe" ascii //weight: 8
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AKFB_2147942902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AKFB!MTB"
        threat_id = "2147942902"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 17 12 16 28 ?? 01 00 0a 13 18 12 16 28 ?? 01 00 0a 13 19 11 17 11 18 58 11 19 58 26 04 03 6f ?? 01 00 0a 59 25 17 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_SKA_2147943865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.SKA!MTB"
        threat_id = "2147943865"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 7b 01 00 00 04 07 6f 20 00 00 0a 6f 63 00 00 06 06 28 20 00 00 06 2d 13 02 02 7b 01 00 00 04 07 6f 20 00 00 0a 28 02 00 00 06 2a 07 17 58 0b 07 02 7b 01 00 00 04 6f 1f 00 00 0a 32 c2}  //weight: 1, accuracy: High
        $x_1_2 = "$12345678-1234-5678-9abc-123456789012" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ATB_2147943901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ATB!MTB"
        threat_id = "2147943901"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 2b 1e 08 6f ?? 00 00 0a 0d 00 00 03 09 16 6a 28 ?? 00 00 06 58 10 01 00 de 05 26 00 00 de 00 00 08 6f ?? 00 00 0a 2d da de 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AGB_2147943914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AGB!MTB"
        threat_id = "2147943914"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 0b 11 08 18 6a 58 20 00 01 00 00 6a 5d d4 91 61 d2 13 1c 11 1a 11 0b 11 08 20 00 01 00 00 6a 5d d4 91 61 d2 13 1d 11 1b 11 0b 11 08 17 6a 58 20 00 01 00 00 6a 5d d4 91 61 d2 13 1e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_BAC_2147943950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.BAC!MTB"
        threat_id = "2147943950"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 08 02 08 91 06 08 06 8e 69 5d 91 61 d2 9c 07 08 07 08 91 19 63 07 08 91 1b 62 60 d2 9c 08 17 58 0c 08 02 8e 69 32 d8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_BAD_2147944387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.BAD!MTB"
        threat_id = "2147944387"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {9c 13 22 16 13 23 2b 20 03 11 22 11 23 91 ?? ?? 00 00 0a 11 0f 1d 17 9c 11 09 11 22 11 23 91 58 13 09 11 23 17 58 13 23 11 23 11 21 32 da 11 15 20 f4 01 00 00 5d 2d 54 11 0f 1e 11 0f 1e 91 16 fe 01 9c 11 0f 1f 09 11 15 20 e8 03 00 00 5d 16 fe 01 9c 1f 64 09 17 58}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_NJA_2147944403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.NJA!MTB"
        threat_id = "2147944403"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "4B1E8AE6-09C8-4480-8399-3D1740EAE277" ascii //weight: 2
        $x_1_2 = {11 0c 25 17 58 13 0c 93 11 05 61 60 13 07 11 0f 1f 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_SKC_2147944448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.SKC!MTB"
        threat_id = "2147944448"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 03 11 06 11 07 91 6f 74 00 00 0a 00 00 11 07 17 58 13 07 11 07 09 fe 04 13 08 11 08 2d e1}  //weight: 1, accuracy: High
        $x_1_2 = {00 02 06 07 6f 71 00 00 0a 0c 04 03 6f 72 00 00 0a 59 0d 09 19 fe 04 16 fe 01 13 04 11 04 2c 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_SKC_2147944448_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.SKC!MTB"
        threat_id = "2147944448"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6f 30 00 00 0a 13 05 04 03 6f 2f 00 00 0a 59 13 06 03 12 05 28 31 00 00 0a 6f 32 00 00 0a 11 06 17 59 25 13 06 16 31 32 03 12 05 28 33 00 00 0a 6f 32 00 00 0a 11 06 17 59 25 13 06 16 31 1b 03 12 05 28 34 00 00 0a 6f 32 00 00 0a 07 17 58 0b 2b 90 06 17 58 0a 16 0b 2b 88}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_SKC_2147944448_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.SKC!MTB"
        threat_id = "2147944448"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 11 0b 17 58 1f 25 5a 11 0e 17 58 1f 65 5a 61 07 61 13 0f 11 0f 11 0d 23 00 00 00 00 00 40 8f 40 5a 69 61 13 0f 02 11 0b 11 0e 6f 1a 00 00 0a 13 10 04 03 6f 1b 00 00 0a 59}  //weight: 1, accuracy: High
        $x_1_2 = {00 11 12 20 cb 03 00 00 5a 11 0f 20 f5 03 00 00 5a 61 20 ff 03 00 00 5f 13 13 06 11 13 1b 63 94 17 11 13 1f 1f 5f 1f 1f 5f 62 5f 16 fe 03 13 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_FormBook_SKC_2147944448_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.SKC!MTB"
        threat_id = "2147944448"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 02 06 07 6f 71 00 00 0a 0c 04 03 6f 72 00 00 0a 59 0d 09 19 fe 04 16 fe 01 13 04 11 04 2c 2e 00 03 12 02 28 73 00 00 0a 6f 74 00 00 0a 00 03 12 02 28 75 00 00 0a 6f 74 00 00 0a 00 03 12 02 28 76 00 00 0a 6f 74 00 00 0a 00 00 2b 56 09 16 fe 02 13 05 11 05 2c 4c 00 19 8d 50 00 00 01 25 16 12 02 28 73 00 00 0a 9c 25 17 12 02 28 75 00 00 0a 9c 25 18 12 02 28 76 00 00 0a 9c 13 06 16 13 07 2b 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_SKC_2147944448_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.SKC!MTB"
        threat_id = "2147944448"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 11 12 20 cb 03 00 00 5a 11 0f 20 f5 03 00 00 5a 61 20 ff 03 00 00 5f 13 13 06 11 13 1b 63 94 17 11 13 1f 1f 5f 1f 1f 5f 62 5f 16 fe 03 13 14 02 11 0f 11 12 6f ?? 00 00 0a 13 15 04 03}  //weight: 1, accuracy: Low
        $x_1_2 = "TravBot.Properties.Resources.resources" ascii //weight: 1
        $x_1_3 = "$8e3f3a97-e034-40d8-b68a-32657072ee96" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_SKC_2147944448_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.SKC!MTB"
        threat_id = "2147944448"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 09 11 10 1f 3d 5a 61 13 11 02 11 0f 11 10 6f 66 00 00 0a 13 12 04 03 6f 67 00 00 0a 59 13 13 11 13 13 14 11 14 19 31 03 19 13 14 11 14 16 2f 03 16 13 14 11 09 16 5f 13 15 11 15 19 5d 13 16 17 11 15 58 19 5d 13 17 18 11 15 58 19 5d 13 18 19 8d 51 00 00 01}  //weight: 1, accuracy: High
        $x_1_2 = "CrudForm.Properties" ascii //weight: 1
        $x_1_3 = "$F3C8A6D2-7B4E-4A9F-B5C1-9E6A2D4F8C7B" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RVK_2147944493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RVK!MTB"
        threat_id = "2147944493"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 1f b6 09 09 09 00 00 00 fa ?? 33 00 16 00 00 01 00 00 00 7e 00 00 00 15 00 00 00 72 00 00 00 ?? 00 00 00 73 00 00 00 06 00 00 00 ed 00 00 00 0b 00 00 00 25 00 00 00 ?? 00 00 00 06 00 00 00 06 00 00 00 09 00 00 00 2e 00 00 00 5e 00 00 00 09 00 00 00 01 00 00 00 05 00 00 00 04 00 00 00 01}  //weight: 1, accuracy: Low
        $x_1_2 = "A9F8E7D6-C5B4-A392-8176-543210987654" ascii //weight: 1
        $x_1_3 = "DeThiLTGD1920.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AG_2147944981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AG!MTB"
        threat_id = "2147944981"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 25 16 11 0a 75 0b 00 00 1b 16 99 d2 9c 25 17 11 0a 74 0b 00 00 1b 17 99 d2 9c 25 18 11 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_EGFB_2147945208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.EGFB!MTB"
        threat_id = "2147945208"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 03 11 21 11 22 91 ?? ?? ?? ?? ?? 00 72 f1 01 00 70 12 22 ?? ?? 00 00 0a ?? ?? 00 00 0a 13 05 00 11 22 17 58 13 22 11 22 11 1a fe 04 13 23 11 23 2d cd}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AMYA_2147945401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AMYA!MTB"
        threat_id = "2147945401"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 2f 6c 02 7b ?? 01 00 04 6f ?? 01 00 0a 02 7b ?? 01 00 04 2f 53 17 8d ?? 00 00 01 25 16 02 7b ?? 01 00 04 03 04 6f ?? 01 00 0a a4 ?? 00 00 01 02 7b ?? 01 00 04 25 2d 16 26 02 02 fe ?? ?? 00 00 06 73 ?? 01 00 0a 25 0a 7d ?? 01 00 04 06 28 ?? 00 00 2b 02 7b ?? 01 00 04 03 04 17 58 6f ?? 01 00 0a 28 ?? 00 00 2b 2a 28 ?? 00 00 2b 2a 02 7b ?? 01 00 04 03 17 58 16 6f ?? 01 00 0a 2a 28 ?? 00 00 2b 2a}  //weight: 5, accuracy: Low
        $x_2_2 = {01 25 16 09 16 18 6f ?? 01 00 0a a2 25 17 72 d4 10 00 70 a2 25 18 11 04 16 18 6f ?? 01 00 0a 6f ?? 01 00 0a a2 25 19 72 d4 10 00 70 a2 25 1a 11 06 2d 07}  //weight: 2, accuracy: Low
        $x_2_3 = {0a 11 05 61 11 0c 6f ?? 00 00 0a 61 13 0f 1b 8d ?? 00 00 01 25 16 12 0f 72 a6 3a 00 70 28 ?? 01 00 0a a2 25 17 72 aa 3a 00 70 a2 25 18}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_ACH_2147945515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.ACH!MTB"
        threat_id = "2147945515"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {05 07 0e 06 23 00 00 00 00 00 00 ?? ?? 19 28 ?? 00 00 06 0c 02 05 07 6f ?? 00 00 0a 0d 03 04 09 08 06 05 07}  //weight: 3, accuracy: Low
        $x_2_2 = {0a 0f 02 28 ?? 00 00 0a 0b 0f 02 28 ?? 00 00 0a 0c 06 07 08 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_BAE_2147945621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.BAE!MTB"
        threat_id = "2147945621"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 27 06 61 06 61 d2 13 27 11 28 16 61 d2 13 28 11 29 06 61 06 61 d2 13 29 11 27 13 2a 11 28 13 2b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AE_2147945976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AE!MTB"
        threat_id = "2147945976"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 0c 07 17 59 8d 62 00 00 01 0d 02 09 16 07 17 59 6f 78 00 00 0a 26 09 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_FMB_2147946003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.FMB!MTB"
        threat_id = "2147946003"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 04 6f ?? 00 00 0a 0a 12 01 fe 15 27 00 00 02 12 01 12 00 28 ?? 00 00 0a 7d c9 01 00 04 12 01 12 00 28 ?? 00 00 0a 7d ca 01 00 04 12 01 12 00 28 ?? 00 00 0a 7d cb 01 00 04 0e 05 0d 09 39 9b 00 00 00 00 23 89 41 60 e5 d0 22 d3 3f 07 7b c9 01 00 04 6c 5a 23 62 10 58 39 b4 c8 e2 3f 07 7b ca 01 00 04 6c 5a 58 23 c9 76 be 9f 1a 2f bd 3f 07 7b cb 01 00 04 6c 5a 58}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_BAG_2147946313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.BAG!MTB"
        threat_id = "2147946313"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 75 00 00 70 0a 06 28 45 00 00 0a 25 26 0b 28 46 00 00 0a 07 16 07 8e 69 ?? ?? 00 00 0a 25 26 0a 28 37 00 00 0a 06 ?? ?? 00 00 0a 25 26 0c 1f 61 6a 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RVL_2147947611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RVL!MTB"
        threat_id = "2147947611"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 1f a2 09 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 99 00 00 00 2c 00 00 00 2c 02 00 00 50 01 00 00 da 00 00 00 01 00 00 00 2d 01 00 00 08 00 00 00 6a 01 00 00 30 00 00 00 12 00 00 00 6d 00 00 00 c0 00 00 00 2d 00 00 00 01 00 00 00 0a 00 00 00 12 00 00 00 05 00 00 00 0b 00 00 00 10}  //weight: 1, accuracy: High
        $x_1_2 = {57 1f a2 29 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 9c 00 00 00 2d 00 00 00 2d 02 00 00 50 01 00 00 da 00 00 00 01 00 00 00 2d 01 00 00 08 00 00 00 6b 01 00 00 30 00 00 00 12 00 00 00 6d 00 00 00 c0 00 00 00 2d 00 00 00 01 00 00 00 01 00 00 00 0a 00 00 00 12 00 00 00 05 00 00 00 0b 00 00 00 0e}  //weight: 1, accuracy: High
        $x_5_3 = "bdca53e8-25ac-4c33-b99d-e71c82d4ee72" ascii //weight: 5
        $x_5_4 = "QLDTDD_FPT.Properties.Resources" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_FormBook_RVM_2147947750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RVM!MTB"
        threat_id = "2147947750"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 7f b6 1d 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 e5 00 00 00 33 00 00 00 c4 00 00 00 07 02 00 00 e1 01 00 00 04 00 00 00 f9 01 00 00 34 00 00 00 b8 01 00 00 01 00 00 00 04 00 00 00 35 00 00 00 09 00 00 00 23 00 00 00 1b 00 00 00 84 00 00 00 32 01 00 00 01 00 00 00 1d 00 00 00 01 00 00 00 01 00 00 00 08 00 00 00 04 00 00 00 09 00 00 00 04 00 00 00 0e}  //weight: 1, accuracy: High
        $x_1_2 = {57 ff b6 3d 09 1e 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 03 01 00 00 ?? 00 00 00 ?? 00 00 00 ?? 02 00 00 e1 01 00 00 04 00 00 00 10 02 00 00 34 00 00 00 a4 02 00 00 01 00 00 00 04 00 00 00 05 00 00 00 ?? 00 00 00 09 00 00 00 23 00 00 00 1b 00 00 00 84 00 00 00 32 01 00 00 01 00 00 00 ?? 00 00 00 01 00 00 00 05 00 00 00 01 00 00 00 08}  //weight: 1, accuracy: Low
        $x_5_3 = "B6F3D8A2-4C7E-4A9B-9F2D-5E8A1C6B4F7D" ascii //weight: 5
        $x_5_4 = "GroupBoxDemo.Properties.Resources" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_FormBook_BAF_2147947930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.BAF!MTB"
        threat_id = "2147947930"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 11 03 16 73 1b 00 00 0a 13 05 38 00 00 00 00 00 73 0d 00 00 0a 13 06 38 00 00 00 00 00 11 05 11 06 ?? ?? 00 00 0a 38 00 00 00 00 11 06 ?? ?? 00 00 0a 13 07 38 00 00 00 00 dd 72 ff ff ff 11 06 39 11 00 00 00 38 00 00 00 00 11 06 ?? ?? 00 00 0a 38 00 00 00 00 dc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RVN_2147947993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RVN!MTB"
        threat_id = "2147947993"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 1d a2 09 09 0d 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 80 00 00 00 15 00 00 00 d8 00 00 00 ab 00 00 00 9f 00 00 00 10 01 00 00 06 00 00 00 21 00 00 00 44 00 00 00 03 00 00 00 07 00 00 00 08 00 00 00 14 00 00 00 01 00 00 00 06 00 00 00 0a 00 00 00 03 00 00 00 04}  //weight: 1, accuracy: High
        $x_1_2 = "E7D2A9C4-6B8F-4E3A-9C1D-7F4B2A8E5C6D" ascii //weight: 1
        $x_1_3 = "BookFlowLibrary.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RVO_2147948322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RVO!MTB"
        threat_id = "2147948322"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 1d b6 09 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 a4 00 00 00 1d 00 00 00 8d 00 00 00 01 01 00 00 d0 00 00 00 8c 01 00 00 05 00 00 00 b7 00 00 00 40 00 00 00 01 00 00 00 01 00 00 00 0b 00 00 00 2e 00 00 00 52 00 00 00 26 00 00 00 01 00 00 00 06 00 00 00 04 00 00 00 05 00 00 00 02 00 00 00 1c}  //weight: 1, accuracy: High
        $x_1_2 = "0a4968f4-6fa2-43b2-927f-4b3aca05eb31" ascii //weight: 1
        $x_1_3 = "AlarmPlus.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AFMB_2147948392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AFMB!MTB"
        threat_id = "2147948392"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 07 17 da 0d 20 1a ba 15 00 13 04 2b 16 08 03 74 ?? 00 00 1b 11 04 91 6f ?? 01 00 0a 00 11 04 17 d6 13 04 11 04 09 31 e5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RVP_2147952231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RVP!MTB"
        threat_id = "2147952231"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 1d a2 09 09 09 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 7d 00 00 00 17 00 00 00 b5 00 00 00 a3 00 00 00 7b 00 00 00 f7 00 00 00 04 00 00 00 84 00 00 00 2c 00 00 00 04 00 00 00 22 00 00 00 3e 00 00 00 08 00 00 00 01 00 00 00 08 00 00 00 07 00 00 00 01}  //weight: 1, accuracy: High
        $x_1_2 = "B2D5F8A1-4C7E-4A9B-8F3D-6A1C9E4B7F2D" ascii //weight: 1
        $x_1_3 = "Used_cars.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RVQ_2147952312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RVQ!MTB"
        threat_id = "2147952312"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 bf a2 3f 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 6e 00 00 00 15 00 00 00 84 00 00 00 58 00 00 00 6b 00 00 00 01 00 00 00 db 00 00 00 34 00 00 00 2b 00 00 00 09 00 00 00 01 00 00 00 0e 00 00 00 04 00 00 00 11 00 00 00 19 00 00 00 01 00 00 00 02 00 00 00 09 00 00 00 03 00 00 00 01 00 00 00 01 00 00 00 06 00 00 00 03 00 00 00 0b 00 00 00 02}  //weight: 1, accuracy: High
        $x_1_2 = "Calculator.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AOKB_2147952317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AOKB!MTB"
        threat_id = "2147952317"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 07 09 19 5f 07 8e 69 5d 94 1f 11 5a 61 0d 11 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_RVR_2147952412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.RVR!MTB"
        threat_id = "2147952412"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 1d a2 09 09 0b 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 87 00 00 00 0d 00 00 00 78 00 00 00 d2 01 00 00 75 00 00 00 eb 00 00 00 04 00 00 00 56 00 00 00 1a 00 00 00 03 00 00 00 0f 00 00 00 18 00 00 00 08 00 00 00 01 00 00 00 08 00 00 00 07 00 00 00 01 00 00 00 03}  //weight: 1, accuracy: High
        $x_1_2 = "12345678-1234-5678-9012-123456789012" ascii //weight: 1
        $x_1_3 = "LotterySimulation.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_BAH_2147952677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.BAH!MTB"
        threat_id = "2147952677"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 16 73 06 00 00 0a 13 05 73 07 00 00 0a 13 06 11 05 11 06 ?? ?? 00 00 0a 11 06 ?? ?? 00 00 0a 13 07 dd 50 00 00 00 11 06 39 07 00 00 00 11 06 ?? ?? 00 00 0a dc 11 05 39 07 00 00 00 11 05 ?? ?? 00 00 0a dc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_BAI_2147952680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.BAI!MTB"
        threat_id = "2147952680"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 13 05 07 ?? ?? 00 00 0a 13 06 11 04 11 05 11 06 ?? ?? 00 00 0a 13 07 03 73 05 00 00 0a 13 08 11 08 11 07 16 73 06 00 00 0a 13 09 73 07 00 00 0a 13 0a 11 09 11 0a ?? ?? 00 00 0a 11 0a ?? ?? 00 00 0a 0c 1f 64 0d dd 0f 00 00 00 11 0a 39 07 00 00 00 11 0a ?? ?? 00 00 0a dc dd 0f 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_GXV_2147953851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.GXV!MTB"
        threat_id = "2147953851"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 04 11 16 1f 3b 5a 61 0e 04 18 62 61 13 17 02 11 15 11 16 6f ?? 00 00 0a 13 18 04 03 6f ?? 00 00 0a 59 13 19 11 19 13 1a 11 1a 19 31 03 19 13 1a 11 1a 16 2f 03 16 13 1a 11 04 16 5f 13 1b 11 1b 19 5d 13 1c 17 11 1b 58 19 5d 13 1d 18 11 1b 58 19 5d 13 1e 19 8d ?? ?? ?? ?? 13 1f 11 1f 16 12 18 28 ?? 00 00 0a 9c 11 1f 17 12 18 28 ?? 00 00 0a 9c 11 1f 18 12 18 28 ?? 00 00 0a 9c 11 1a 16 31 0f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MCJ_2147954210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MCJ!MTB"
        threat_id = "2147954210"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 0a 11 0f 1f 90 01 01 5a 11 0a 1b 63 61 61 13 0a 16 13 10}  //weight: 1, accuracy: High
        $x_1_2 = {4d 00 61 00 74 00 68 00 00 07 53 00 54 00 44 00 00 31 44 00 65 00 70 00 65 00 6e 00 64 00 65 00 6e 00 63 00 79 00 50 00 72 00 6f 00 70 00 65 00 72 00 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_FormBook_AI_2147954451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AI!MTB"
        threat_id = "2147954451"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 13 1d 11 1d 16 12 16 28 ?? 00 00 0a 9c 11 1d 17 12 16 28 ?? 00 00 0a 9c 11 1d 18 12 16 28}  //weight: 1, accuracy: Low
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "DebuggableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggingModes" ascii //weight: 1
        $x_1_5 = "DesktopProject.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_SO_2147955096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.SO!MTB"
        threat_id = "2147955096"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5a 11 0e 1a 63 61 61 13 0e}  //weight: 1, accuracy: High
        $x_1_2 = "SolarSystem.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AO_2147955223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AO!MTB"
        threat_id = "2147955223"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 13 40 11 40 16 12 39 28 ?? 00 00 0a 9c 11 40 17 12 39 28 ?? 00 00 0a 9c 11 40 18 12 39 28}  //weight: 1, accuracy: Low
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "DebuggableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AKI_2147955372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AKI!MTB"
        threat_id = "2147955372"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 2d 03 17 2b 01 15 0b 04 6c 0e 05 5a 69 0e 06 58 0c 03 16 06 7b ?? 00 00 04 6f ?? 00 00 0a 07 5a 07 5a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_SI_2147956636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.SI!MTB"
        threat_id = "2147956636"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 11 13 02 6f 85 00 00 0a fe 04 16 fe 01 13 2a 11 2a 2c 05 38 fd 00 00 00 11 14 02 6f 86 00 00 0a fe 04 16 fe 01 13 2b 11 2b 2c 0f 00 11 13 17 58 13 13 16 13 14 38 d6 00 00 00 06 6f a9 00 00 0a 03 fe 04 16 fe 01 13 2c 11 2c 2c 05 38 c4 00 00 00 02 11 13 11 14 6f aa 00 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = "JuegoMemoriaColores.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_SI_2147956636_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.SI!MTB"
        threat_id = "2147956636"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 0a 02 6f 1d 00 00 0a 3c 0a 01 00 00 11 0b 02 6f 1e 00 00 0a 32 0b 11 0a 17 58 13 0a 16 13 0b 2b de 07 6f 32 00 00 0a 06 3c e9 00 00 00 02 11 0a 11 0b 6f}  //weight: 1, accuracy: High
        $x_1_2 = "PS_Timer.Properties.Resources.resources" ascii //weight: 1
        $x_1_3 = "$445fd492-3746-4da4-a4b5-0689cbf44f9b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MCP_2147957322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MCP!MTB"
        threat_id = "2147957322"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SXVM.0Harmony.bin" ascii //weight: 2
        $x_2_2 = "SXVM.payload.bin" ascii //weight: 2
        $x_1_3 = "1d5e4f8a9c2b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_MCP_2147957322_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.MCP!MTB"
        threat_id = "2147957322"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 00 ed 00 74 00 75 00 6c 00 6f 00 01 07 73 00 68 00 70 00 00 01 00 07 4c 00 6f 00 61 [0-10] 43 00 61 00 72 00 75 00 62 00 62 00 69 00 2e 00 4d 00 65 00 74 00 72 00 6f 00 4c 00 61 00 79 00 6f 00 75 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_AKK_2147957614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.AKK!MTB"
        threat_id = "2147957614"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 fe 01 13 15 11 15 2c 05 38 ff 00 00 00 02 11 05 11 06 6f ?? 00 00 0a 13 0a 03 07 6f ?? 00 00 0a 59 13 0b 07 12 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 0b 17 59 25 13 0b 16 fe 02 16 fe 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FormBook_BAJ_2147958727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBook.BAJ!MTB"
        threat_id = "2147958727"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 12 09 28 ?? 00 00 0a 6f ?? 00 00 0a 12 09 28 ?? 00 00 0a 6e 20 df 03 00 00 6a 5a 12 09 28 ?? 00 00 0a 6e 20 bb 01 00 00 6a 5a 58 12 09 28 ?? 00 00 0a 6e 20 c7 00 00 00 6a 5a 58 13 0d 11 0d 07 6a 61 13 0d 11 0d 19 6a 5f 18 6a 33 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

