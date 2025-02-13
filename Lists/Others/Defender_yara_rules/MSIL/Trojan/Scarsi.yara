rule Trojan_MSIL_Scarsi_NEAA_2147836092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scarsi.NEAA!MTB"
        threat_id = "2147836092"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {73 10 00 00 0a 25 28 11 00 00 0a 28 06 00 00 06 6f 12 00 00 0a 6f 13 00 00 0a 28 01 00 00 2b 6f 15 00 00 0a 2a}  //weight: 10, accuracy: High
        $x_1_2 = "Samsung" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Scarsi_ABEJ_2147836112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scarsi.ABEJ!MTB"
        threat_id = "2147836112"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 0a 2b 0b 18 2b 0b 1f 10 2b 0e 2a 02 2b f3 03 2b f2 6f ?? ?? ?? 0a 2b ee 28 ?? ?? ?? 0a 2b eb}  //weight: 2, accuracy: Low
        $x_1_2 = "InvokeMember" ascii //weight: 1
        $x_1_3 = "GetDomain" ascii //weight: 1
        $x_1_4 = "GetResponseStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Scarsi_ABGU_2147837959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scarsi.ABGU!MTB"
        threat_id = "2147837959"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 13 04 16 13 05 11 04 12 05 28 17 00 00 0a 06 09 28 0a 00 00 06 13 06 07 09 11 06 6f 18 00 00 0a de 0c 11 05 2c 07 11 04 28 19 00 00 0a dc 09 18 58 0d 09 06 6f 1a 00 00 0a 32 c4}  //weight: 1, accuracy: High
        $x_1_2 = {02 03 18 6f 1d 00 00 0a 1f 10 28 1e 00 00 0a 2a}  //weight: 1, accuracy: High
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "GetResponseStream" ascii //weight: 1
        $x_1_5 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Scarsi_ABIP_2147838866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scarsi.ABIP!MTB"
        threat_id = "2147838866"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {09 11 05 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 09 17 6f ?? ?? ?? 0a 06 13 06 08 09 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 07 11 07 11 06 16 11 06 8e 69 6f ?? ?? ?? 0a de 0c 11 07 2c 07 11 07 6f ?? ?? ?? 0a dc 08 6f ?? ?? ?? 0a 13 08 de 14}  //weight: 3, accuracy: Low
        $x_1_2 = "SymmetricAlgorithm" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Scarsi_AS_2147839029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scarsi.AS!MTB"
        threat_id = "2147839029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 16 0a 2b 17 11 04 09 06 09 8e 69 5d 91 08 06 91 61 d2 6f ?? ?? ?? 0a 06 17 58 0a 06 08 8e 69 32 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Scarsi_AS_2147839029_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scarsi.AS!MTB"
        threat_id = "2147839029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b f1 0b 2b f8 02 50 06 91 16 2c 18 26 02 50 06 02 50 07 91 9c 02 50 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e6 06 07 32 da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Scarsi_ABIO_2147839120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scarsi.ABIO!MTB"
        threat_id = "2147839120"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0a 2b 6a 00 28 ?? ?? ?? 06 73 ?? ?? ?? 0a 0b 73 ?? ?? ?? 0a 0c 07 16 73 ?? ?? ?? 0a 73 ?? ?? ?? 0a 0d 09 08 6f ?? ?? ?? 0a de 0a 09 2c 06 09 6f ?? ?? ?? 0a dc 08 6f ?? ?? ?? 0a 13 04 de 34}  //weight: 2, accuracy: Low
        $x_1_2 = "InvokeMember" ascii //weight: 1
        $x_1_3 = "GetTypes" ascii //weight: 1
        $x_1_4 = "Ajtbtbctc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Scarsi_RB_2147839382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scarsi.RB!MTB"
        threat_id = "2147839382"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 06 11 04 06 8e 69 5d 91 08 11 04 91 61 d2 6f ?? 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Scarsi_NCS_2147839767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scarsi.NCS!MTB"
        threat_id = "2147839767"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 30 00 00 0a 6f ?? ?? 00 0a 07 1f 10 8d ?? ?? 00 01 25 d0 ?? ?? 00 04 28 ?? ?? 00 0a 6f ?? ?? 00 0a 06 07 6f ?? ?? 00 0a 17 73 ?? ?? 00 0a 25 02 16 02 8e 69 6f ?? ?? 00 0a 6f ?? ?? 00 0a 06 28 ?? ?? 00 06 28 ?? ?? 00 06 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "Okvtbek" ascii //weight: 1
        $x_1_3 = "WindowsFormsApp1.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Scarsi_MBBM_2147839787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scarsi.MBBM!MTB"
        threat_id = "2147839787"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4D-5A-9}@-}3@@@-}4@@@-FF-FF@@-B8@@@@@@" wide //weight: 1
        $x_1_2 = "System.Convert" ascii //weight: 1
        $x_1_3 = "KKDEWHJJUDHIS44" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Scarsi_MB_2147840361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scarsi.MB!MTB"
        threat_id = "2147840361"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {06 0c 16 0d 08 12 03 28 0f 00 00 0a 06 07 02 07 18 6f 10 00 00 0a 1f 10 28 11 00 00 0a 6f 12 00 00 0a de 0a}  //weight: 10, accuracy: High
        $x_5_2 = {57 15 a2 09 09 08 00 00 00 5a a4 01 00 14 00 00 01 00 00 00 22 00 00 00 03 00 00 00 01 00 00 00 0a 00 00 00 03 00 00 00 24 00 00 00 11 00 00 00 03 00 00 00 01 00 00 00 01 00 00 00 02 00 00 00 02}  //weight: 5, accuracy: High
        $x_2_3 = "TryDequeue" ascii //weight: 2
        $x_2_4 = "Enqueue" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Scarsi_MC_2147840705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scarsi.MC!MTB"
        threat_id = "2147840705"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 06 18 5b 08 06 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 06 18 58 0a 06 09 32 e3}  //weight: 5, accuracy: Low
        $x_1_2 = "SkipVerification" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Scarsi_CAA_2147841055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scarsi.CAA!MTB"
        threat_id = "2147841055"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6f 25 00 00 0a 1f 10 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 08 18 58 0c 08 06 1a 2c f9 32 da 07 6f 28 00 00 0a 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Scarsi_ABJZ_2147841602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scarsi.ABJZ!MTB"
        threat_id = "2147841602"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 09 06 09 8e 69 5d 91 08 06 91 61 d2 6f ?? ?? ?? 0a 06 17 58 0a 06 08 8e 69 32 e3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Scarsi_ASI_2147843166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scarsi.ASI!MTB"
        threat_id = "2147843166"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1e 2d 14 26 06 18 5b 8d ?? ?? ?? 01 18 2d 0b 26 16 1a 2d 09 26 2b 21 0a 2b ea 0b 2b f3 0c 2b f5 07 08 18 5b 02 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 08 18 58 0c 08 06 32 e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Scarsi_ABHY_2147849942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scarsi.ABHY!MTB"
        threat_id = "2147849942"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 02 08 18 6f 2b 00 00 0a 1f 10 28 2c 00 00 0a 6f 2d 00 00 0a 08 18 58 0c 08 06 32 e3 07 6f 2e 00 00 0a 2a}  //weight: 2, accuracy: High
        $x_1_2 = "ToByte" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Scarsi_AAEW_2147850713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scarsi.AAEW!MTB"
        threat_id = "2147850713"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 8e 69 17 da 13 0b 16 13 0c 2b 1b 11 04 11 0c 09 11 0c 9a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 0c 17 d6 13 0c 11 0c 11 0b 31 df}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Scarsi_ABTN_2147896752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scarsi.ABTN!MTB"
        threat_id = "2147896752"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dyn+am+icInv+oke" wide //weight: 1
        $x_1_2 = "Syste+m.Refl+ection.As+sembly" wide //weight: 1
        $x_1_3 = "Ge+tExp+ortedTy+pes" wide //weight: 1
        $x_1_4 = "Lo+ad" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Scarsi_MA_2147900026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scarsi.MA!MTB"
        threat_id = "2147900026"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {06 0c 16 0d 08 12 03 28 19 00 00 0a 06 07 02 07 18 6f 1a 00 00 0a 1f 10 28 1b 00 00 0a 6f 1c 00 00 0a de 0a}  //weight: 10, accuracy: High
        $x_2_2 = "Shutdowns" ascii //weight: 2
        $x_2_3 = "Interrupted" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Scarsi_DSAA_2147902494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scarsi.DSAA!MTB"
        threat_id = "2147902494"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0d 2b 1f 00 07 09 8f ?? 00 00 01 13 04 11 04 11 04 47 02 09 6a 06 6e 5d d4 91 61 d2 52 00 09 17 d6 0d 09 08 fe 02 16 fe 01 13 05 11 05 2d d4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

