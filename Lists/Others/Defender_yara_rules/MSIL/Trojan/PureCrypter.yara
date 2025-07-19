rule Trojan_MSIL_PureCrypter_RDA_2147843769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.RDA!MTB"
        threat_id = "2147843769"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d4e9ff35-13e2-4c74-a49e-ecb1eaaa3fac" ascii //weight: 1
        $x_1_2 = "File Signature Verification" ascii //weight: 1
        $x_1_3 = "Vrlawadz" ascii //weight: 1
        $x_1_4 = "//80.66.75.37/a-Xmifagl.dll" wide //weight: 1
        $x_1_5 = "Eoxhinemlvxygfpeh" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_RDB_2147894558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.RDB!MTB"
        threat_id = "2147894558"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 23 00 00 0a 28 24 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_ACP_2147894678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.ACP!MTB"
        threat_id = "2147894678"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 27 00 00 0a 0c 00 2b 31 16 2b 31 2b 36 2b 3b 00 09 08 6f ?? ?? ?? 0a 00 00 de 11 09 2c 07 09 6f ?? ?? ?? 0a 00 19 2c f6 16 2d f9 dc 16 2d 08 08 6f ?? ?? ?? 0a 13 04 de 33 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_PSIL_2147899375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.PSIL!MTB"
        threat_id = "2147899375"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 03 11 02 11 04 11 02 8e 69 5d 91 11 01 11 04 91 61 d2 6f ?? ?? ?? 0a 20 ?? ?? ?? 00 7e 07 00 00 04 7b 42 00 00 04 3a 26 ff ff ff 26 20 ?? ?? ?? 00 38 1b ff ff ff 28 17 00 00 06 72 79 00 00 70 6f ?? ?? ?? 0a 13 02 38 8d ff ff ff 11 03 28 18 00 00 06 13 05 38 ?? ?? ?? 00 dd a3 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_APU_2147900865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.APU!MTB"
        threat_id = "2147900865"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {14 fe 03 13 09 20 00 00 d5 09 00 fe 0e 0e 00 00 fe 0d 0e 00 48 68 d3 13 0d 2b cb 11 09 2c 71 20 03 00 0b 7a fe 0e 0e 00 00 fe 0d 0e 00 00 48 68 d3 13 0d 2b b1 2b 00 00 11 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_APU_2147900865_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.APU!MTB"
        threat_id = "2147900865"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 11 04 07 11 04 91 09 11 04 09 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 da}  //weight: 4, accuracy: Low
        $x_3_2 = "103.228.37.51/HOST1/Reytnpg.dat" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_OHAA_2147912064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.OHAA!MTB"
        threat_id = "2147912064"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 06 72 01 00 00 70 28 ?? 01 00 06 6f ?? 00 00 0a 06 72 5b 00 00 70 28 ?? 01 00 06 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b}  //weight: 2, accuracy: Low
        $x_2_2 = {13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 08 6f ?? 00 00 0a 28 ?? 00 00 0a 06}  //weight: 2, accuracy: Low
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_UNAA_2147919645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.UNAA!MTB"
        threat_id = "2147919645"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0b 16 0c 38 19 00 00 00 06 07 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 08 18 58 0c 08 07 6f 0d 00 00 0a 3f}  //weight: 4, accuracy: Low
        $x_1_2 = "GetByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_URAA_2147919757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.URAA!MTB"
        threat_id = "2147919757"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 05 2a 00 11 09 72 ?? 00 00 70 28 ?? 00 00 06 72 ?? 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 13 07}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_VTAA_2147920467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.VTAA!MTB"
        threat_id = "2147920467"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0d 09 08 17 73 ?? 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 0a de 0f}  //weight: 3, accuracy: Low
        $x_2_2 = {07 2b a7 28 ?? 00 00 0a 2b a7 28 ?? 00 00 0a 2b a7 6f ?? 00 00 0a 2b a2}  //weight: 2, accuracy: Low
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_VZAA_2147920643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.VZAA!MTB"
        threat_id = "2147920643"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0c 08 07 17 73 ?? 00 00 0a 0d 02 28 ?? 00 00 06 13 04 09 11 04 28 ?? 00 00 2b 16 11 04 28 ?? 00 00 2b 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 05 dd 27}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_APC_2147921665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.APC!MTB"
        threat_id = "2147921665"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 16 0c 2b 1a 06 08 02 08 91 07 08 07 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 08 17 58 0c 08 02 8e 69 32 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_ARAX_2147922654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.ARAX!MTB"
        threat_id = "2147922654"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 05 12 02 28 ?? ?? ?? 0a 13 06 12 02 28 ?? ?? ?? 0a 13 07 03 11 05 16 61 d2 6f ?? ?? ?? 0a 00 03 11 06 16 61 d2 6f ?? ?? ?? 0a 00 03 11 07 16 61 d2 6f ?? ?? ?? 0a 00 2b 15 03 6f ?? ?? ?? 0a 19 58 04 31 03 16 2b 01 17 13 08 11 08 2d a9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_ARAX_2147922654_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.ARAX!MTB"
        threat_id = "2147922654"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 11 09 17 58 20 ff 00 00 00 5f 13 09 11 07 11 04 11 09 95 58 20 ff 00 00 00 5f 13 07 02 11 04 11 09 8f ?? ?? ?? 01 11 04 11 07 8f ?? ?? ?? 01 28 ?? ?? ?? 06 00 11 04 11 09 95 11 04 11 07 95 58 20 ff 00 00 00 5f 13 11 11 06 19 5e 16 fe 01 13 12 11 12 2c 10 00 11 08 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 13 08 00 09 11 06 07 11 06 91 11 04 11 11 95 61 28 ?? ?? ?? 0a 9c 11 06 17 58 13 06 00 11 06 6e 09 8e 69 6a fe 04 13 13 11 13 3a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_APR_2147926660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.APR!MTB"
        threat_id = "2147926660"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 04 07 11 04 91 09 11 04 09 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 da 06 08 6f ?? 00 00 0a 06 16 6f}  //weight: 3, accuracy: Low
        $x_1_2 = "103.228.37.51/HOST1/Vyigyafn.wav" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_EA_2147927496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.EA!MTB"
        threat_id = "2147927496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 11 04 7e 09 00 00 04 7b 02 00 00 04 6f 1e 00 00 0a a2 11 04 17 58 13 04 11 04 08 8e 69 32 e0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_PLLWH_2147930817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.PLLWH!MTB"
        threat_id = "2147930817"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {11 05 11 09 09 11 09 91 03 11 09 07 5d 91 61 d2 9c 11 09 17 58 13 09 11 09 08 32 e4}  //weight: 6, accuracy: High
        $x_5_2 = {09 11 04 25 17 58 13 04 02 11 08 91 9c 11 08 04 17 58 58 13 08 11 08 06 32 e6}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_ZHK_2147936791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.ZHK!MTB"
        threat_id = "2147936791"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 0b 07 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 07 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 07 6f ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 0c}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_SVCB_2147938399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.SVCB!MTB"
        threat_id = "2147938399"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {38 5a 00 00 00 11 04 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 13 03 20 00 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a c3 ff ff ff 26}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_ATQA_2147938556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.ATQA!MTB"
        threat_id = "2147938556"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 13 01 11 01 16 11 01 8e 69 6f ?? 00 00 0a 13 03 20 00 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? ff ff ff 26 20 01 00 00 00 38 ?? ff ff ff 11 04 72 93 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 20 02 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? ff ff ff 26 20 02 00 00 00 38}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_AUQA_2147938650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.AUQA!MTB"
        threat_id = "2147938650"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1a 25 2c 11 8d ?? 00 00 01 0b 06 07 16 07 8e 69 6f ?? 00 00 0a 26 16 2d f1 07 16 28 ?? 00 00 0a 0c 06 16 73 ?? 00 00 0a 0d 2b 2e 8d ?? 00 00 01 2b 2a 16 2b 2b 1a 2c 02 2b 14 2b 28 2b 2a 2b 2b 11 05 08 11 05 59 6f ?? 00 00 0a 58 13 05 11 05 08 32 e7 11 04 13 06 de 2d 08 2b cf 13 04 2b d2 13 05 2b d1 11 05 2b d4 09 2b d3 11 04 2b d1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_AKWA_2147943480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.AKWA!MTB"
        threat_id = "2147943480"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 25 07 6f ?? 00 00 0a 25 08 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 0d 09 6f ?? 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? 00 00 0a 13 05 03 72 ?? 00 00 70 11 05 6f ?? 00 00 06 17 13 06 dd}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_ZNV_2147944768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.ZNV!MTB"
        threat_id = "2147944768"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 06 20 00 01 00 00 6f ?? 00 00 0a 06 20 ?? 76 8f 37 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 20 ?? 76 8f 37 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 02 73 ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 08 07 16 73 ?? 00 00 0a 13 04}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_BAA_2147945618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.BAA!MTB"
        threat_id = "2147945618"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 01 38 1e 00 00 00 11 01 16 ?? ?? 00 00 0a 13 02 38 00 00 00 00 11 00 16 73 15 00 00 0a 13 03 38 11 00 00 00 11 00 11 01 16 1a ?? ?? 00 00 0a 26 38 d1 ff ff ff 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_ABAB_2147946872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.ABAB!MTB"
        threat_id = "2147946872"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0c 08 06 28 ?? 00 00 0a 07 28 ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 02 28 ?? 00 00 06 75 ?? 00 00 1b 13 06 11 05 11 06 16 11 06 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 07 dd}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

