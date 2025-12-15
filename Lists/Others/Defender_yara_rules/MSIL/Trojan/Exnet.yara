rule Trojan_MSIL_Exnet_AAIC_2147833493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Exnet.AAIC!MTB"
        threat_id = "2147833493"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Exnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 02 8e 69 8d 2f 00 00 01 0b 16 0c 2b 15 00 07 08 02 08 91 06 08 06 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 02 8e 69 fe 04 0d 09 2d e1}  //weight: 2, accuracy: High
        $x_1_2 = "BossBotnet.Client" ascii //weight: 1
        $x_1_3 = "sqlsrvs.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Exnet_ABPT_2147843314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Exnet.ABPT!MTB"
        threat_id = "2147843314"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Exnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "GAdminLib.Properties.Resources.resources" ascii //weight: 5
        $x_1_2 = "GetObject" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "GAdminLib" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Exnet_AE_2147846425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Exnet.AE!MTB"
        threat_id = "2147846425"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Exnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 1e 00 00 0a 0a 02 6f d5 00 00 0a 2c 2a 28 1e 00 00 0a 06 28 d6 00 00 0a 0b 12 01 28 d7 00 00 0a 03 6c 36 07 02 6f d8 00 00 0a 2a 20 e8 03 00 00 28 c5 00 00 0a 2b ce}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Exnet_AX_2147848100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Exnet.AX!MTB"
        threat_id = "2147848100"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Exnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 06 02 6f ?? ?? ?? 0a 0b 73 1f 00 00 0a 0c 08 03 6f ?? ?? ?? 0a 0d 07 28 ?? ?? ?? 0a 13 04 11 04 72 5b 4b 00 70 6f ?? ?? ?? 0a 13 05 72 77 4b 00 70 13 06 18 8d ?? ?? ?? 01 25 16 11 06 a2 25 17 09 a2 13 07 11 05 72 e9 4b 00 70 20 00 01 00 00 14 14 11 07 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "varesaint.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Exnet_PSVG_2147888132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Exnet.PSVG!MTB"
        threat_id = "2147888132"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Exnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 02 8e 69 18 da 0b 73 ?? 00 00 0a 0c 07 0d 16 13 04 2b 1a 08 02 11 04 9a 28 ?? 00 00 0a 1f 59 da b4 6f ?? 00 00 0a 00 11 04 17 d6 13 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Exnet_NE_2147894990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Exnet.NE!MTB"
        threat_id = "2147894990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Exnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mf add credit FULL.g.resources" ascii //weight: 1
        $x_1_2 = "MreR.ib+c" ascii //weight: 1
        $x_1_3 = "MreR.ib+b" ascii //weight: 1
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
        $x_1_5 = "ReadProcessMemory" ascii //weight: 1
        $x_1_6 = "mf_addcredit.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Exnet_PSED_2147899360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Exnet.PSED!MTB"
        threat_id = "2147899360"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Exnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 40 00 00 0a 28 41 ?? ?? ?? 03 61 13 04 1d 13 05 00 11 05 17 fe 01 2c 03 18 13 05 00 11 05 20 4f ff ff ff fe 1c 1c 00 00 01 59 7e 08 00 00 04 16 94 58 fe 01 2c 1c 06 17 d6 0a 7e 08 00 00 04 17 94 fe 1c 17 00 00 01 59 7e 08 00 00 04 18 94 59 13 05 00 11 05 1f 8e fe 1c 1a 00 00 01 59 7e 08 00 00 04 19 94 58 fe 01 2c 1a 06 07 31 8f 20 60 fe ff ff fe 1c 17 00 00 01 59 7e 08 00 00 04 1a 94 58 13 05 00 11 05 1b fe 01 2c 05 2b dc 1c 13 05 00 11 05 19 fe 01 2c 0c 02 6f 42 ?? ?? ?? 17 da 0b 1a 13 05 00 11 05 1d fe 01 2c 24 08 11 04 28 43 ?? ?? ?? 28 44 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "MemoryStream" ascii //weight: 1
        $x_1_3 = "WriteLine" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Exnet_KAA_2147924317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Exnet.KAA!MTB"
        threat_id = "2147924317"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Exnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 08 02 07 17 28 ?? 00 00 0a 28 ?? 00 00 0a 61 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 07 17 58 b5 0b 07 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Exnet_SWA_2147925456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Exnet.SWA!MTB"
        threat_id = "2147925456"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Exnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "#EtherShield" ascii //weight: 2
        $x_1_2 = "CaptureScreen" ascii //weight: 1
        $x_1_3 = "AntiDllInjection" ascii //weight: 1
        $x_1_4 = "HooksDetection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Exnet_EAQE_2147939539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Exnet.EAQE!MTB"
        threat_id = "2147939539"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Exnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 50 07 02 50 8e b7 5d 02 50 07 02 50 8e b7 5d 91 03 07 03 8e b7 5d 91 61 02 50 07 17 d6 02 50 8e b7 5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 07 17 d6 0b 07 08 31 c5}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Exnet_MKV_2147939575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Exnet.MKV!MTB"
        threat_id = "2147939575"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Exnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 07 6f 21 00 00 0a 02 8e 69 07 8e 69 59 8d 18 00 00 01 0c 02 07 8e 69 08 16 08 8e 69 28 ?? 00 00 0a 06 17 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 08 73 24 00 00 0a 0d 09 06 6f ?? 00 00 0a 16 73 26 00 00 0a 13 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Exnet_MKA_2147959465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Exnet.MKA!MTB"
        threat_id = "2147959465"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Exnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {2c 75 00 06 72 5e 02 00 70 1f 28 6f 1a 00 00 0a 13 08 06 72 76 02 00 70 1f 28 6f 1a 00 00 0a 13 09 06 72 8e 02 00 70 1f 28 6f 1a 00 00 0a 13 0a 11 08 2d 02 2b 0a 11 08 14 14 28 1b 00 00 0a 00 11 09 2d 02 2b 13}  //weight: 15, accuracy: High
        $x_10_2 = {0b 07 2c 30 00 06 72 ac 02 00 70 1f 28 6f 22 00 00 0a 0c 08 2d 02 2b 1b 08 14 17 8d 13 00 00 01 25 16 7e 23 00 00 0a 8c 23 00 00 01 a2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

