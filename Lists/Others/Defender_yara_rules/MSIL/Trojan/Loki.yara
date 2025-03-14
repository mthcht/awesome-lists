rule Trojan_MSIL_Loki_NEA_2147829226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Loki.NEA!MTB"
        threat_id = "2147829226"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 07 06 06 6f 2b 00 00 06 5b 5a 58 6f 2c 00 00 06 09 17 58 0d 09 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Loki_NEB_2147830090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Loki.NEB!MTB"
        threat_id = "2147830090"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 06 08 6f 1d 00 00 0a 06 18 6f 1e 00 00 0a 02 0d 06 6f 1f 00 00 0a 09 16}  //weight: 1, accuracy: High
        $x_1_2 = "TripleDESCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Loki_NEAB_2147834184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Loki.NEAB!MTB"
        threat_id = "2147834184"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 00 0a 73 01 00 00 06 28 04 00 00 06 6f ?? 00 00 0a ?? 2d 04 26 26 2b 07}  //weight: 5, accuracy: Low
        $x_5_2 = {07 03 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 08 18 58 0c 08 06 32 e3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Loki_NEAC_2147835615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Loki.NEAC!MTB"
        threat_id = "2147835615"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {d0 18 00 00 01 28 11 00 00 0a 02 75 1b 00 00 01 28 12 00 00 0a 16 8d 10 00 00 01 6f 13 00 00 0a 26 2a}  //weight: 10, accuracy: High
        $x_5_2 = "DataCenter_OnDial" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Loki_NEAE_2147836095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Loki.NEAE!MTB"
        threat_id = "2147836095"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "get_Bonebreaker" ascii //weight: 5
        $x_5_2 = "SpikedJamadhar" ascii //weight: 5
        $x_5_3 = "get_Katana" ascii //weight: 5
        $x_5_4 = "CrystalDagger" ascii //weight: 5
        $x_5_5 = "BLYAT InBLYAT vokBLYAT eBLYAT" wide //weight: 5
        $x_5_6 = "BLYAT GBLYAT eBLYAT tBLYAT TBLYAT yBLYAT pBLYAT e" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Loki_AAHS_2147851802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Loki.AAHS!MTB"
        threat_id = "2147851802"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 04 07 74 ?? 00 00 1b 11 04 1f 09 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 1b 13 09 2b 8f 08 17 d6 0c 19 13 09 2b 86}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Loki_SG_2147912600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Loki.SG!MTB"
        threat_id = "2147912600"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 6a 0d 2b 5b 06 17 58 20 ff 00 00 00 5f 0a 08 07 06 95 58 20 ff 00 00 00 5f 0c 07 06 95 13 04 07 06 07 08 95 9e 07 08 11 04 9e 11 07 09 d4 91 13 0e 07 06 95 07 08 95 58 d2 13 0f 11 0f d2 13 10 07 11 10 95 d2 13 11 11 05 09 d4 11 0e 6e 11 11 20 ff 00 00 00 5f 6a 61 d2 9c 09 17 6a 58 0d 09 11 05 8e 69 17 59 6a fe 02 16 fe 01 13 12 11 12 2d 92}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Loki_A_2147914504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Loki.A!MTB"
        threat_id = "2147914504"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 11 04 91 07 61 06 09 91 61 13 05 08 11 04 11 05 d2 9c 09 13 07}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Loki_A_2147914504_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Loki.A!MTB"
        threat_id = "2147914504"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 1c 00 00 01 13 14 11 09 28 2d 00 00 0a 16 11 14 16 1a 28 2e 00 00 0a 11 0a 28 2d 00 00 0a 16 11 14 1a 1a 28 2e 00 00 0a 11 0b 28 2d 00 00 0a 16 11 14 1e 1a}  //weight: 2, accuracy: High
        $x_1_2 = "7cfc33c2-8ffc-452a-97ef-af0fcbc82af4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Loki_B_2147914952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Loki.B!MTB"
        threat_id = "2147914952"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 11 01 02 8e 69 5d 02 11 01 02 8e 69 5d 91 11 00 11 01 11 00 8e 69 5d 91 61 28 ?? ?? ?? 06 02 11 01 17 58 02 8e 69 5d 91 28 ?? ?? ?? 06 59 20 00 01 00 00 58 20 00 01 00 00 5d 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Loki_C_2147914995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Loki.C!MTB"
        threat_id = "2147914995"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 1a 58 0a}  //weight: 2, accuracy: High
        $x_2_2 = {11 04 17 58}  //weight: 2, accuracy: High
        $x_2_3 = {06 16 08 74 ?? ?? ?? 1b 06 1a}  //weight: 2, accuracy: Low
        $x_2_4 = {0b 07 07 5a 1a 5a 8d}  //weight: 2, accuracy: High
        $x_4_5 = {01 0d 08 74 ?? ?? ?? 1b 1a 09 74 ?? ?? ?? 1b 16 09 75 ?? ?? ?? 1b 8e 69 28}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Loki_D_2147915065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Loki.D!MTB"
        threat_id = "2147915065"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 11 04 91 07 61 06 09 91 61 13 05 08 11 04 11 05 d2 9c 09}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Loki_E_2147917668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Loki.E!MTB"
        threat_id = "2147917668"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 04 03 8e 69 5d 03 8e 69 58 03 8e 69 5d 91}  //weight: 2, accuracy: High
        $x_2_2 = {03 17 58 04 5d 04 58 04 5d}  //weight: 2, accuracy: High
        $x_2_3 = {03 04 05 5d 05 58 05 5d 91}  //weight: 2, accuracy: High
        $x_4_4 = {04 05 5d 05 58 05 5d 0a 03 06 91 0e 04 61 0e 05 59}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Loki_MBWD_2147927368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Loki.MBWD!MTB"
        threat_id = "2147927368"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "QKgifx9HZ5gTZKMjs" ascii //weight: 2
        $x_1_2 = {57 32 45 79 71 6b 5a 67 00 38 5a 6d 4d 6e 6a 59 47 55 54 4b 76 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Loki_KAC_2147930181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Loki.KAC!MTB"
        threat_id = "2147930181"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "fMlo79P8D+j/pPLL7vyG1P2Pc" ascii //weight: 4
        $x_3_2 = "NGX0nOu/blPv4NWmVlDwefgMjWd" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

