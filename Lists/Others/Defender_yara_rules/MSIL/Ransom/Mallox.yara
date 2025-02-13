rule Ransom_MSIL_Mallox_MKV_2147844578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Mallox.MKV!MTB"
        threat_id = "2147844578"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 2d 1f 26 7e ?? ?? ?? 04 fe ?? ?? ?? 00 06 73 ?? ?? ?? 0a 25 1d 2d 03 26 2b 07 80 ?? ?? ?? 04 2b 00 6f ?? ?? ?? 06 de 03 26 de 00 d0 ?? ?? ?? 01 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 74 ?? ?? ?? 01 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 16 8d ?? ?? ?? 01 6f ?? ?? ?? 0a 74 ?? ?? ?? 01 2a 65 00 7e ?? ?? ?? 04 7e ?? ?? ?? 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Mallox_MKA_2147848114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Mallox.MKA!MTB"
        threat_id = "2147848114"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 61 60 13 07 1f 0e 13 0e 38 ?? ?? ?? ff 11 0b 74 ?? ?? ?? 1b 8e 69 13 08 17 13 09 1b 13 0e 38 ?? ?? ?? ff 11 04 74 ?? ?? ?? 01 11 05 11 0a 75 ?? ?? ?? 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 75 09 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f ?? ?? ?? 0a 26 1a 13 0e 38 ?? ?? ?? ff 11 09 17 58 13 09 1b 13 0e 38 ?? ?? ?? ff 11 09 11 07 31 08 19 13 0e 38 ?? ?? ?? ff 1f 0d 2b f5 11 04 75 ?? ?? ?? 01 6f ?? ?? ?? 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Mallox_MA_2147900419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Mallox.MA!MTB"
        threat_id = "2147900419"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 9f a3 29 09 0b 00 00 00 00 00 00 00 00 00 00 01 00 00 00 6e 00 00 00 f3 00 00 00 fb 04 00 00 34 0d 00 00 fb 05 00 00 04}  //weight: 1, accuracy: High
        $x_1_2 = "428f73ff-0a6e-4221-bca9-7db65bcc34b3" ascii //weight: 1
        $x_1_3 = "Zjwimxfxz.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Mallox_MB_2147900426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Mallox.MB!MTB"
        threat_id = "2147900426"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {57 9d b6 3d 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 c2 00 00 00 33}  //weight: 3, accuracy: High
        $x_1_2 = "00da1206-afe6-4c4a-a88f-5ff06ca700d0" ascii //weight: 1
        $x_1_3 = "b6277946ccc47c.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Mallox_AA_2147900484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Mallox.AA!MTB"
        threat_id = "2147900484"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://80.66.75.40" wide //weight: 10
        $x_1_2 = "ReflectBroadcaster" wide //weight: 1
        $x_1_3 = "LoginFactory" ascii //weight: 1
        $x_1_4 = "RevertFactory" ascii //weight: 1
        $x_1_5 = "AwakeFactory" ascii //weight: 1
        $x_1_6 = "ComputeProxy" ascii //weight: 1
        $x_1_7 = "jsonWriter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Mallox_MC_2147901173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Mallox.MC!MTB"
        threat_id = "2147901173"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 09 03 6f ?? ?? ?? 0a 09 59 6f ?? ?? ?? 0a 13 0d 07 11 0d 02 7b 18 00 00 04 73 4c 00 00 0a 6f ?? ?? ?? 0a 07 13 0e 11 0e 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Mallox_LL_2147901185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Mallox.LL!MTB"
        threat_id = "2147901185"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 1b 11 09 11 23 11 21 61 19 11 1a 58 61 11 2e 61 d2 9c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Mallox_NN_2147901432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Mallox.NN!MTB"
        threat_id = "2147901432"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {91 1b 62 2b 1f 7b ad 03 ?? ?? 2b 1b 7b ab 03 ?? ?? 17 58 91 61 ?? ?? ?? ?? ?? 2a 02 2b d4 02 2b d3 02 2b d7 02 2b de 02}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Mallox_LA_2147901471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Mallox.LA!MTB"
        threat_id = "2147901471"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 0c 17 58 93 11 05 61 13 06 1a 13 0e 38 0e ?? ?? ?? 11 0c 19 58 13 0c 11 06 1f 1f 5f 11 06 20 c0 ?? ?? ?? 5f 17 63 60 13 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Mallox_SG_2147901661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Mallox.SG!MTB"
        threat_id = "2147901661"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 fe 09 00 70 17 8d 9d 00 00 01 25 16 1f 2c 9d 28 d4 00 00 0a 0d}  //weight: 2, accuracy: High
        $x_2_2 = {72 03 0c 00 70 28 e0 00 00 0a 11 04 28 e1 00 00 0a 13 10 11 10 28 e2 00 00 0a 26 11 10 06 7b 28 03 00 04 72 13 0c 00 70 28 ad 00 00 0a 13 11 11 11 28 e3 00 00 0a 2d 2d 11 11 28 e4 00 00 0a 25 11 0e 16 11 0e 8e 69 6f 1f 00 00 0a 6f 17 00 00 0a 11 11 14 1a 28 69 01 00 06 26 11 10 14 1a 28 69 01 00 06 26 11 11 28 e5 00 00 0a 13 0f de 03}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

