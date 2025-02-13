rule Trojan_MSIL_RiseProStealer_AAIS_2147852329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RiseProStealer.AAIS!MTB"
        threat_id = "2147852329"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 8e 69 5d 7e ?? 00 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? 00 00 06 03 08 1b 58 1b 59 17 58 03 8e 69 5d 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 1e 2c ad}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RiseProStealer_AANC_2147889027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RiseProStealer.AANC!MTB"
        threat_id = "2147889027"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 05 07 28 ?? 00 00 06 00 11 05 17 28 ?? 00 00 06 00 11 05 09 28 ?? 00 00 06 00 00 11 05 28 ?? 00 00 06 13 06 11 06 11 04 16 11 04 8e 69 28 ?? 00 00 06 13 07}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RiseProStealer_AAOF_2147890313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RiseProStealer.AAOF!MTB"
        threat_id = "2147890313"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "33648d89-b00c-47ef-9100-1c5557768c3a" ascii //weight: 1
        $x_1_2 = "PolymodXT.exe" wide //weight: 1
        $x_1_3 = "Reverse" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RiseProStealer_AAPX_2147891679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RiseProStealer.AAPX!MTB"
        threat_id = "2147891679"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 0a 11 03 28 ?? 00 00 06 20 01 00 00 00 28 ?? 00 00 06 3a ?? ff ff ff 26 38 ?? ff ff ff 00 00 11 0a 6f ?? 00 00 0a 13 06 20 00 00 00 00 28 ?? 00 00 06 3a ?? ff ff ff 26 38 ?? ff ff ff 00 11 06 11 0b 16 11 0b 8e 69 6f ?? 00 00 0a 13 0c}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RiseProStealer_AAUD_2147894253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RiseProStealer.AAUD!MTB"
        threat_id = "2147894253"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 08 11 03 6f ?? 00 00 0a 38 00 00 00 00 00 00 11 08 6f ?? 00 00 0a 13 06 38 00 00 00 00 00 11 06 11 04 16 11 04 8e 69 28 ?? 00 00 06 13 0b}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RiseProStealer_AAUM_2147894538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RiseProStealer.AAUM!MTB"
        threat_id = "2147894538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 05 11 03 6f ?? 00 00 0a 38 00 00 00 00 00 00 11 05 6f ?? 00 00 0a 13 06 38 00 00 00 00 00 11 06 11 0a 16 11 0a 8e 69 6f ?? 00 00 0a 13 07}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RiseProStealer_AAXJ_2147897416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RiseProStealer.AAXJ!MTB"
        threat_id = "2147897416"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 8e 69 5d 18 58 1b 58 1d 59 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 18 58 1b 58 1d 59 91 61 28 ?? 00 00 0a 02 08 20 89 10 00 00 58 20 88 10 00 00 59 02 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 1b 2c 89 08 17 58 0c 08 6a 02 8e 69 17 59 6a 06 17 58 6e 5a 31 98}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RiseProStealer_AXAA_2147900807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RiseProStealer.AXAA!MTB"
        threat_id = "2147900807"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 09 09 16 09 8e 69 28 ?? 00 00 06 13 06}  //weight: 2, accuracy: Low
        $x_2_2 = {06 13 09 17 28 ?? 00 00 06 3a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RiseProStealer_BQAA_2147901193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RiseProStealer.BQAA!MTB"
        threat_id = "2147901193"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 09 11 06 9c 06 08 91 06 09 91 58 20 00 01 00 00 5d 13 07 02 11 05 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 07 91 61 d2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RiseProStealer_SK_2147901398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RiseProStealer.SK!MTB"
        threat_id = "2147901398"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b 29 11 0a 6f 03 00 00 0a 13 26 11 0b 11 26 11 14 59 61 13 0b 11 14 1f 0a 28 6c 00 00 06 11 0b 58 17 28 6c 00 00 06 63 59 13 14 11 0a 28 af 01 00 06 2d ce de 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RiseProStealer_CNAA_2147901713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RiseProStealer.CNAA!MTB"
        threat_id = "2147901713"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 25 11 04 6f ?? ?? 00 0a 00 25 17 28 ?? ?? 00 06 00 25 18 28 ?? ?? 00 06 00 25 07 6f ?? ?? 00 0a 00 13 08}  //weight: 2, accuracy: Low
        $x_2_2 = {0a 13 09 11 09 09 16 09 8e 69 28 ?? ?? 00 06 13 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RiseProStealer_CPAA_2147901729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RiseProStealer.CPAA!MTB"
        threat_id = "2147901729"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 25 11 04 28 ?? ?? 00 06 00 25 17 28 ?? ?? 00 06 00 25 18 28 ?? ?? 00 06 00 25 07 28 ?? ?? 00 06 00 13 08}  //weight: 2, accuracy: Low
        $x_2_2 = {06 13 09 11 09 09 16 09 8e 69 28 ?? ?? 00 06 13 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RiseProStealer_ARA_2147902717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RiseProStealer.ARA!MTB"
        threat_id = "2147902717"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {14 0a 02 16 3e ?? ?? ?? 00 28 ?? ?? ?? 0a 02 18 5d 3a 16 00 00 00 28 ?? ?? ?? 06 0a 28 ?? ?? ?? 0a 06 28 ?? ?? ?? 0a 38 05 00 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = "Wvqzdswh.Properties.Resources" ascii //weight: 2
        $x_2_3 = "Uspdacafxr" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RiseProStealer_HSAA_2147905126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RiseProStealer.HSAA!MTB"
        threat_id = "2147905126"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 01 11 02 11 15 7b ?? 00 00 04 91 58 20 00 01 00 00 5d 13 01}  //weight: 2, accuracy: Low
        $x_2_2 = {05 11 0c 8f ?? 00 00 01 25 71 ?? 00 00 01 11 02 11 10 91 61 d2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RiseProStealer_HWAA_2147905238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RiseProStealer.HWAA!MTB"
        threat_id = "2147905238"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 13 11 13 7b ?? 00 00 04 17 58 20 00 01 00 00 5d}  //weight: 2, accuracy: Low
        $x_2_2 = {05 11 0c 8f ?? 00 00 01 25 71 ?? 00 00 01 11 02 11 0e 91 61 d2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RiseProStealer_A_2147912049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RiseProStealer.A!MTB"
        threat_id = "2147912049"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 94 19 18 8d ?? 00 00 01 13 93 11 93 16 14 a2}  //weight: 2, accuracy: Low
        $x_2_2 = {11 94 17 05 50 a2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RiseProStealer_B_2147912602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RiseProStealer.B!MTB"
        threat_id = "2147912602"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 05 19 17 8d ?? 00 00 01 13 03 11 03 16 04 a2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RiseProStealer_C_2147914668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RiseProStealer.C!MTB"
        threat_id = "2147914668"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {16 04 61 00 16 04 32 00 16 04 56 00 16 04 79 00 16 04 62 00 16 04 6d 00 16 04 56 00 16 04 73 00 16 04 4d 00 16 04 7a 00 16 04 49 00 16 04 3d 00}  //weight: 4, accuracy: High
        $x_2_2 = {16 04 62 00 16 04 6e 00 16 04 52 00 16 04 6b 00 16 04 62 00 16 04 47 00 16 04 77 00 16 04 3d}  //weight: 2, accuracy: High
        $x_2_3 = {16 04 55 00 16 04 6d 00 16 04 56 00 16 04 7a 00 16 04 64 00 16 04 57 00 16 04 31 00 16 04 6c 00 16 04 56 00 16 04 47 00 16 04 68 00 16 04 79 00 16 04 5a 00 16 04 57 00 16 04 46 00 16 04 6b}  //weight: 2, accuracy: High
        $x_2_4 = {16 04 56 00 16 04 32 00 16 04 39 00 16 04 33 00 16 04 4e 00 16 04 6a 00 16 04 52 00 16 04 54 00 16 04 5a 00 16 04 58 00 16 04 52 00 16 04 55 00 16 04 61 00 16 04 48 00 16 04 4a 00 16 04 6c 00 16 04 59 00 16 04 57 00 16 04 52 00 16 04 44 00 16 04 62 00 16 04 32 00 16 04 35 00 16 04 30 00 16 04 5a 00 16 04 58 00 16 04 68 00 16 04 30}  //weight: 2, accuracy: High
        $x_2_5 = {16 04 55 00 16 04 32 00 16 04 56 00 16 04 30 00 16 04 56 00 16 04 47 00 16 04 68 00 16 04 79 00 16 04 5a 00 16 04 57 00 16 04 46 00 16 04 6b 00 16 04 51 00 16 04 32 00 16 04 39 00 16 04 75 00 16 04 64 00 16 04 47 00 16 04 56 00 16 04 34 00 16 04 64 00 16 04 41 00 16 04 3d 00 16 04 3d}  //weight: 2, accuracy: High
        $x_2_6 = {16 04 56 00 16 04 32 00 16 04 39 00 16 04 33 00 16 04 4e 00 16 04 6a 00 16 04 52 00 16 04 48 00 16 04 5a 00 16 04 58 00 16 04 52 00 16 04 55 00 16 04 61 00 16 04 48 00 16 04 4a 00 16 04 6c 00 16 04 59 00 16 04 57 00 16 04 52 00 16 04 44 00 16 04 62 00 16 04 32 00 16 04 35 00 16 04 30 00 16 04 5a 00 16 04 58 00 16 04 68 00 16 04 30}  //weight: 2, accuracy: High
        $x_2_7 = {16 04 52 00 16 04 32 00 16 04 56 00 16 04 30 00 16 04 56 00 16 04 47 00 16 04 68 00 16 04 79 00 16 04 5a 00 16 04 57 00 16 04 46 00 16 04 6b 00 16 04 51 00 16 04 32 00 16 04 39 00 16 04 75 00 16 04 64 00 16 04 47 00 16 04 56 00 16 04 34 00 16 04 64 00 16 04 41 00 16 04 3d 00 16 04 3d}  //weight: 2, accuracy: High
        $x_2_8 = {16 04 56 00 16 04 6d 00 16 04 6c 00 16 04 79 00 16 04 64 00 16 04 48 00 16 04 56 00 16 04 68 00 16 04 62 00 16 04 45 00 16 04 46 00 16 04 73 00 16 04 62 00 16 04 47 00 16 04 39 00 16 04 6a 00 16 04 52 00 16 04 58 00 16 04 67 00 16 04 3d 00}  //weight: 2, accuracy: High
        $x_2_9 = {16 04 56 00 16 04 33 00 16 04 4a 00 16 04 70 00 16 04 64 00 16 04 47 00 16 04 56 00 16 04 51 00 16 04 63 00 16 04 6d 00 16 04 39 00 16 04 6a 00 16 04 5a 00 16 04 58 00 16 04 4e 00 16 04 7a 00 16 04 54 00 16 04 57 00 16 04 56 00 16 04 74 00 16 04 62 00 16 04 33 00 16 04 4a 00 16 04 35}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

