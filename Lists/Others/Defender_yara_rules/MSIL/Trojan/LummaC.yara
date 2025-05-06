rule Trojan_MSIL_LummaC_CXII_2147852915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.CXII!MTB"
        threat_id = "2147852915"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 03 03 28 ?? ?? ?? ?? 17 59 fe 01 13 05 38 ?? ?? ?? ?? 02 02 8e 69 17 59 91 1f 70 61 13 01 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_CXIJ_2147852916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.CXIJ!MTB"
        threat_id = "2147852916"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 02 11 04 02 11 04 91 11 01 61 11 00 11 03 91 61 d2 9c 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_GZZ_2147905284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.GZZ!MTB"
        threat_id = "2147905284"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8f 1b 00 00 01 25 71 1b 00 00 01 1f 2e 58 d2 81 1b 00 00 01}  //weight: 10, accuracy: High
        $x_1_2 = "IKnkcnjbzjZBoaa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_MBZQ_2147905431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.MBZQ!MTB"
        threat_id = "2147905431"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0b 07 1f 20 8d 1e 00 00 01 25 d0 ce 00 00 04 28 ?? 00 00 0a 6f 8f 00 00 0a 07 1f 10}  //weight: 3, accuracy: Low
        $x_2_2 = {52 75 6e 6e 69 6e 67 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e 00 43 6f 72 72 65 63 74 00 4d 53 47}  //weight: 2, accuracy: High
        $x_2_3 = {67 42 4d 74 68 65 70 6f 5a 53 4c 31 5a 56 4b 70 65 41 00 55 77 56 75 71 4c 6c 4c 4a 76 70 72 41 6f 53 33 66 63 00 50 51}  //weight: 2, accuracy: High
        $x_1_4 = "Angelo" ascii //weight: 1
        $x_1_5 = "Correct" ascii //weight: 1
        $x_1_6 = "RemoteObjects" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_MBZR_2147905432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.MBZR!MTB"
        threat_id = "2147905432"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 65 76 65 72 62 6e 61 74 69 6f 6e 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e 00 43 6f 72 72 65 63 74 00 4d 53 47 5f 4e 45 54 00 4f 62 6a 65 63 74 00 50 72 6f 67 72 61 6d 00 41 6e 67 65 6c 6f 00 44 67 61 73 79 75 64 67 75 79 67 69 75 78 48}  //weight: 1, accuracy: High
        $x_1_2 = {66 4a 68 69 73 75 41 49 55 4f 00 54 68 72 53 67 74 72 6a 79 74 00 52 65 6d 6f 74 65 4f 62 6a 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_MBZR_2147905432_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.MBZR!MTB"
        threat_id = "2147905432"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 2b 03 17 2b 00 3a ?? 00 00 00 06 6f ?? 03 00 0a 11 06 6f ?? 03 00 0a 16 73 58 03 00 0a 13 0d 11 0d 11 07 28 4f 18 00 06 de 14 11 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {2b 21 02 7b ?? 05 00 04 07 06 6f ?? ?? ?? 0a 20 ?? 1d 1b be 20 ?? 35 de fb 58 20 ?? 6b 14 ed 61 6a 61 9f 07 20 a3 0c 4d c8}  //weight: 1, accuracy: Low
        $x_5_3 = "Rpyoidpf." ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_LummaC_MBZS_2147905667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.MBZS!MTB"
        threat_id = "2147905667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f 72 00 00 0a 07 08 6f 73 00 00 0a 13 05 28 ?? 00 00 06 13 06 11 06 11 05 17 73 74 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {43 61 73 69 73 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e 00 43 6f 72 72 65 63 74 00 4d 53 47 5f 4e 45 54 00 4f 62 6a 65 63 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AMME_2147905753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AMME!MTB"
        threat_id = "2147905753"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 11 11 8f ?? 00 00 01 25 71 ?? 00 00 01 11 ?? 11 ?? 28 ?? 00 00 06 a5 ?? 00 00 01 61 d2 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_MBZU_2147906055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.MBZU!MTB"
        threat_id = "2147906055"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 71 1a 00 00 01 20 88 00 00 00 61 d2 81 1a 00 00 01 03 50 06 ?? 1a 00 00 01 25 71 1a 00 00 01 1f 2e 58 d2}  //weight: 1, accuracy: Low
        $x_1_2 = {46 72 69 65 6e 64 6c 79 2e 65 78 65 00 4b 74 7a 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_ASGE_2147906192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.ASGE!MTB"
        threat_id = "2147906192"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "QzpcV2luZG93c1xNaWNyb3NvZnQuTkVUXEZyYW1ld29ya1x2NC4wLjMwMzE5XE1TQnVpbGQuZXhl" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_MBZT_2147906603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.MBZT!MTB"
        threat_id = "2147906603"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {43 6f 72 72 65 63 74 00 4d 53 47 5f 4e 45 54 00 4f 62 6a 65 63 74 00 50 72 6f 67 72 61 6d 00 41 6e 67 65 6c 6f [0-96] 52 65 6d 6f 74 65 4f 62 6a 65 63 74 73}  //weight: 10, accuracy: Low
        $x_1_2 = "RijndaelManaged" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_MBZV_2147907026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.MBZV!MTB"
        threat_id = "2147907026"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3c 4d 6f 64 75 6c 65 3e 00 43 6f 72 72 65 63 74 00 4d 53 47 5f 4e 45 54 00 4f 62 6a 65 63 74 00 3c 3e 63 5f 5f 44 69 73 70 6c 61 79 43 6c 61 73 73 35}  //weight: 1, accuracy: High
        $x_1_2 = "rivateImplementationDetails>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_CCID_2147909161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.CCID!MTB"
        threat_id = "2147909161"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 08 03 08 1f 09 5d 9a 28 ?? 00 00 0a 02 08 91 28 ?? 00 00 06 b4 9c 08 17 d6 0c 08 07 31 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_MDAA_2147909719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.MDAA!MTB"
        threat_id = "2147909719"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 07 02 07 91 66 d2 9c 02 07 8f ?? 00 00 01 25 71 ?? 00 00 01 1f 72 58 d2 81 ?? 00 00 01 02 07 8f ?? 00 00 01 25 71 ?? 00 00 01 1f 34 59 d2 81 ?? 00 00 01 00 07 17 58 0b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_RDA_2147911388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.RDA!MTB"
        threat_id = "2147911388"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 04 60 03 66 04 66 60 5f 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AMAJ_2147915323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AMAJ!MTB"
        threat_id = "2147915323"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 5d 91 13 ?? 11 ?? 08 20 00 01 00 00 5d 58 11 ?? 58 20 00 01 00 00 5d 13 ?? 11 ?? 11 ?? 19 5a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2}  //weight: 2, accuracy: Low
        $x_1_2 = {5a 20 00 01 00 00 5d d2 0c 06 07 08 9c 00 07 17 58 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AZ_2147917091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AZ!MTB"
        threat_id = "2147917091"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZCnwQyuczHNVZsLbVfaNtAuK.dll" ascii //weight: 1
        $x_1_2 = "VGFmjPREyWEsbjHmeHebQcQAmJ" ascii //weight: 1
        $x_1_3 = "LcrVaCVWmQbNGePKXQvFtVyp" ascii //weight: 1
        $x_1_4 = "YsooMXpGMiFwvybtqHIkaTRdC" ascii //weight: 1
        $x_1_5 = "cTnXHzFElfSUJxItbwZosDJXAsr" ascii //weight: 1
        $x_1_6 = "PfdxUKDVsmHGffSewIrTbKRl.dll" ascii //weight: 1
        $x_1_7 = "XcDvbkQnFxVKtUKZuwJGytHA.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_ASI_2147917450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.ASI!MTB"
        threat_id = "2147917450"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qzekfGDlOWqqjFUbvVomt.dll" ascii //weight: 1
        $x_1_2 = "qtKXquyyZSHQAVEPow.dll" ascii //weight: 1
        $x_1_3 = "etzxpPqlTDXRFxYUWstnmRWizVO" ascii //weight: 1
        $x_1_4 = "rtFQzEWPdrWnkSRhzczkNOVpBFy" ascii //weight: 1
        $x_1_5 = "AMtNVpbyBnJSKkhMOPgMUVSfqRTO.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AMAF_2147919284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AMAF!MTB"
        threat_id = "2147919284"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {91 66 d2 9c 02 11 ?? 8f ?? 00 00 01 25 71 ?? 00 00 01 20 ?? ?? ?? ?? 58 d2 81 ?? 00 00 01 02 11 ?? 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 59 d2 81 ?? 00 00 01 00 11 ?? 17 58 13 ?? 11 ?? 02 8e 69 fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_EZ_2147919555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.EZ!MTB"
        threat_id = "2147919555"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "375c5eff-0650-4301-85ef-382cfefa9adf" ascii //weight: 2
        $x_2_2 = "c:\\56zm\\xzd9\\obj\\Releas\\Zaq1.pdbpdb" ascii //weight: 2
        $x_1_3 = "CallWindowProcA" ascii //weight: 1
        $x_1_4 = "Pewterer Hearses Intersession" ascii //weight: 1
        $x_1_5 = "Bargello Encirclements" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AMAK_2147920636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AMAK!MTB"
        threat_id = "2147920636"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 01 00 00 5d 0d 06 08 91 13 ?? 06 08 06 09 91 9c 06 09 11 ?? 9c 06 08 91 06 09 91 58 20 00 01 00 00 5d 13 [0-80] 91 61 d2 81 [0-15] 11 13 17 58 13 13 11 13 03 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AMA_2147921040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AMA!MTB"
        threat_id = "2147921040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 5b 26 11 ?? 6e 11 ?? 6a 5b 26 11 [0-50] 0a 26 03 11 ?? 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 ?? 91 61 d2 81 ?? 00 00 01 de 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AMA_2147921040_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AMA!MTB"
        threat_id = "2147921040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {9c 06 08 91 06 09 91 58 20 00 01 00 00 5d 13 [0-50] 03 11 ?? 28 ?? 00 00 0a 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 ?? 28 ?? 00 00 0a 91 61 d2 81 ?? 00 00 01 de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_WQAA_2147921691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.WQAA!MTB"
        threat_id = "2147921691"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "KRevolutionizing renewable energy with advanced solar and storage solutions." ascii //weight: 2
        $x_2_2 = "HelioCore Energy Suite" ascii //weight: 2
        $x_1_3 = "HelioCore Innovations Inc." ascii //weight: 1
        $x_1_4 = "HelioCore Innovations Trademark" ascii //weight: 1
        $x_1_5 = "$b7c8d9e0-f1a2-4324-bd5e-67890abcdef0" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_WSAA_2147921692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.WSAA!MTB"
        threat_id = "2147921692"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "LPioneering the future of technology with innovative and efficient solutions." ascii //weight: 2
        $x_2_2 = "Element IO Innovations Inc." ascii //weight: 2
        $x_1_3 = "Element IO Advanced Suite" ascii //weight: 1
        $x_1_4 = "Element IO Innovations Trademark" ascii //weight: 1
        $x_1_5 = "$0c784f02-e0f5-43a1-947a-aea218fd31df" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_ZAA_2147921738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.ZAA!MTB"
        threat_id = "2147921738"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 25 16 07 a2 25 17 72 27 03 00 70 28 ?? ?? 00 0a 72 2f 03 00 70 72 a9 03 00 70 7e 42 00 00 0a 28 ?? ?? 00 0a 28 ?? ?? 00 0a a2 25 18 17 8c 71 00 00 01 a2 25 19 17 8d 20 00 00 01 25 16 72 b7 03 00 70 a2 a2 14 0d 12 03 28 ?? ?? 00 06 28 34 00 00 0a 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AMF_2147922294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AMF!MTB"
        threat_id = "2147922294"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 02 06 02 06 91 66 d2 9c 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 58 d2 81 ?? 00 00 01 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 59 d2 81 ?? 00 00 01 00 06 17 58 0a 06 02 8e 69 fe 04 0b 07 2d bc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AMJ_2147922746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AMJ!MTB"
        threat_id = "2147922746"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 26 16 13 ?? 12 ?? 28 ?? 00 00 0a 28 ?? 00 00 0a 13 ?? 03 11 ?? 91 13 ?? 06 11 ?? 91 13 ?? 28 ?? 00 00 0a 11 ?? 11 ?? 61 d2 13}  //weight: 4, accuracy: Low
        $x_1_2 = {6e 5b 6d 13 [0-20] 6e 58 6d 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_RDC_2147924338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.RDC!MTB"
        threat_id = "2147924338"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 08 02 08 91 07 08 07 6f 21 00 00 0a 5d 6f 22 00 00 0a 61 d2 9c 08 17 58 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_APCA_2147925647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.APCA!MTB"
        threat_id = "2147925647"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {02 06 8f 26 00 00 01 25 71 26 00 00 01 1f 45 59 d2 81 26 00 00 01 02 06 8f 26 00 00 01 25 71 26 00 00 01 1f 29 59 d2 81 26 00 00 01 00 08}  //weight: 3, accuracy: High
        $x_2_2 = {02 06 02 06 91 66 d2 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AZCA_2147925952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AZCA!MTB"
        threat_id = "2147925952"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "develop moon inspire energy it network banana develop black solution" ascii //weight: 2
        $x_2_2 = "white improve support object dark" ascii //weight: 2
        $x_2_3 = "integrate understand she" ascii //weight: 2
        $x_1_4 = "power complex blue" ascii //weight: 1
        $x_1_5 = "$0d6fc9e6-d8e9-406e-88c3-67ce86b38de5" ascii //weight: 1
        $x_1_6 = "they complex she" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_ALU_2147926138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.ALU!MTB"
        threat_id = "2147926138"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 16 0d 16 13 04 2b 27 08 11 04 02 11 04 91 07 61 06 09 91 61 d2 9c 09 03 6f ?? 00 00 0a 17 59 2e 05 09 17 58 2b 01 16 0d 11 04 17 58 13 04 11 04 02 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_ALU_2147926138_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.ALU!MTB"
        threat_id = "2147926138"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b9 00 77 96 6a ?? ?? ?? ?? ?? 95 bb d7 2a a1 f5 1d 92 e0 e4 13 f1 e4 05 07 84 1c 05 ed 19}  //weight: 2, accuracy: Low
        $x_1_2 = "YvonneGraceEleanor" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_ALU_2147926138_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.ALU!MTB"
        threat_id = "2147926138"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 30 11 2d 11 2f 91 58 11 2e 11 2f 91 58 20 00 01 00 00 5d 13 30 11 2d 11 30 91 13 32 11 2d 11 30 11 2d 11 2f 91 9c 11 2d 11 2f 11 32 9c 11 2f 17 58}  //weight: 2, accuracy: High
        $x_3_2 = {11 2f 17 58 11 31 5d 13 2f 11 30 11 2d 11 2f 91 58 11 31 5d 13 30 73 ?? 00 00 0a 13 66 11 66 11 2d 11 30 91 6f ?? 00 00 0a 11 2d 11 30 11 2d 11 2f 91 9c 11 2d 11 2f 11 66}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AVCA_2147926578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AVCA!MTB"
        threat_id = "2147926578"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "service communicate them produce planet direct planet rough learn build" ascii //weight: 3
        $x_2_2 = "$6300505e-ddd5-4bf0-9245-596d0067f453" ascii //weight: 2
        $x_2_3 = "support we connect" ascii //weight: 2
        $x_1_4 = "we new you project new" ascii //weight: 1
        $x_1_5 = "object organize yellow" ascii //weight: 1
        $x_1_6 = "collaborate cosmos you" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_DA_2147926785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.DA!MTB"
        threat_id = "2147926785"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2f 00 2f 00 31 00 39 00 33 00 2e 00 32 00 33 00 33 00 2e 00 32 00 35 00 34 00 2e 00 30 00 2f 00 [0-50] 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_10_2 = {2f 2f 31 39 33 2e 32 33 33 2e 32 35 34 2e 30 2f [0-50] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_1_3 = "powershell.exe" ascii //weight: 1
        $x_1_4 = "runas" ascii //weight: 1
        $x_1_5 = "C:\\Windows\\Temp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_LummaC_ALN_2147926857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.ALN!MTB"
        threat_id = "2147926857"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d4 f6 e4 9c 38 10 77 6b b3 ce 36 30 ba a6 d0 92 53 36 59 62 0f 33 e3 f4 56 94 18 14 bb 04 e8 26 52 4f 29 92 e8 4f f1 18 82 9c a6}  //weight: 1, accuracy: High
        $x_2_2 = "integrate network red idea you she solve inspire vision red" wide //weight: 2
        $x_3_3 = "LiamBritainVioletNathan.exeROD" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_NL_2147926991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.NL!MTB"
        threat_id = "2147926991"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "dark service explore" ascii //weight: 3
        $x_2_2 = "destroy old we" ascii //weight: 2
        $x_2_3 = "IsLogging" ascii //weight: 2
        $x_1_4 = "energy rough star" ascii //weight: 1
        $x_1_5 = "$5dfa8755-6d23-4d61-a4f6-6a3f2f42c443" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_ALA_2147927951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.ALA!MTB"
        threat_id = "2147927951"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 bc fa 4a 03 d3 c1 57 51 3f 38 49 f6 fb 5a ca 9a a5 6b 15 90 2e 97 ce c1 51 63 a9 cc 12 e2 0d 6b 88}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_ASGH_2147928238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.ASGH!MTB"
        threat_id = "2147928238"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "dJUlgvSZpdCgWTQzgwoIznJ.dll" ascii //weight: 2
        $x_1_2 = "NEJhTxHyewesCoDXyLlJJhqb.dll" ascii //weight: 1
        $x_1_3 = "fvXlxJdzSMOtTAgbQwqdlFnyoLo" ascii //weight: 1
        $x_1_4 = "AnKMgjNuTdaMMEVlegARKeQm" ascii //weight: 1
        $x_2_5 = "9FDA7AF569387AB23DEAB3DF6E8401CDB82C961CFEF5627CB560BFD96DB536A6" ascii //weight: 2
        $x_1_6 = "w't4z}FTM;jYC$}Pybpk4jFB" ascii //weight: 1
        $x_1_7 = "V[fa6OgSE\"mn<" ascii //weight: 1
        $x_1_8 = "gDkyS}I#15nkS" ascii //weight: 1
        $x_2_9 = "32F585707B9A5F9805D3DF3A366255E1D258CA4AA9281B14A8CDE2F4902E7595" ascii //weight: 2
        $x_1_10 = "<D@4_\" \\Ra\"Mp@=-ZLq1PN#}" ascii //weight: 1
        $x_1_11 = "0VLMx{{)y8*3#" ascii //weight: 1
        $x_1_12 = "SamuelAvaChloe.jkqw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_LummaC_ALM_2147928489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.ALM!MTB"
        threat_id = "2147928489"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a1 56 4d e4 eb f7 61 9b 49 c4 d4 52 2a 2c 43 6e b6 5b be 1e fc f9 36 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_ALM_2147928489_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.ALM!MTB"
        threat_id = "2147928489"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 08 91 06 09 91 58 20 00 01 00 00 5d 13 06 02 11 05 8f 1d 00 00 01 25 47 06 11 06 91 61 d2 52 11 05 17 58 13 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_ALM_2147928489_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.ALM!MTB"
        threat_id = "2147928489"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 02 16 09 16 09 8e 69 28 ?? 00 00 0a 06 09 6f ?? 00 00 0a 02 8e 69 09 8e 69 59 8d ?? 00 00 01 13 04 02 09 8e 69 11 04 16 11 04 8e 69 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_ALM_2147928489_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.ALM!MTB"
        threat_id = "2147928489"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {09 06 08 91 58 07 08 91 58 20 00 01 00 00 5d 0d 06 09 91 13 04 06 09 06 08 91 9c 06 08 11 04 9c 08 17 58}  //weight: 3, accuracy: High
        $x_2_2 = {06 08 91 06 09 91 58 20 00 01 00 00 5d 13 06 02 11 05 8f 1c 00 00 01 25 47 06 11 06 91 61 d2 52 11 05 17 58}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_BJ_2147928578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.BJ!MTB"
        threat_id = "2147928578"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {14 0b 00 28 ?? 00 00 06 0b dd ?? 00 00 00 26 de f1 07 39 ?? 00 00 00 73 ?? 00 00 0a 0c 08 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 0b dd ?? 00 00 00 08 39 ?? 00 00 00 08 6f ?? 00 00 0a dc 28 ?? 00 00 0a 07 6f ?? 00 00 0a 0d 09 14 28}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_GNS_2147928579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.GNS!MTB"
        threat_id = "2147928579"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 16 0c 2b 1c 00 07 08 7e ?? ?? ?? ?? 06 7e ?? ?? ?? ?? 8e 69 6f ?? ?? ?? 0a 9a a2 00 08 17 58 0c 08 1a fe 04 0d 09 2d dc}  //weight: 10, accuracy: Low
        $x_1_2 = "downloadedfile.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AXGA_2147928728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AXGA!MTB"
        threat_id = "2147928728"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 06 02 06 91 66 d2 9c 02 06 8f ?? 00 00 01 25 47 1f 69 59 d2 52 02 06 8f ?? 00 00 01 25 47 1f 34 58 d2 52 00 06 17 58 0a 06 02 8e 69 fe 04 0b 07 2d cc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AMCY_2147929674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AMCY!MTB"
        threat_id = "2147929674"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 0c 09 06 08 91 58 20 00 01 00 00 5d 0d 06 09 91 13 ?? 06 09 06 08 91 9c 06 08 11 06 9c 06 08 91 06 09 91 58 20 00 01 00 00 5d [0-16] 25 47 06 11 ?? 91 61 d2 52 11 ?? 17 58 13 05 11 05 03 3f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_KAC_2147929676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.KAC!MTB"
        threat_id = "2147929676"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {77 ff 54 75 e3 6f c7 8e 1d a2 72 e5 ca d9 4e fe 8c 18 30 60 80 6e 15 30 4f d6 1c}  //weight: 4, accuracy: High
        $x_3_2 = {90 e8 15 80 de 6a c9 ef 9c 39 73 44 81 02 05 3c 09 00 a2 73 e7 ce e2 f4 e9}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_ACIA_2147929873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.ACIA!MTB"
        threat_id = "2147929873"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 06 02 06 91 66 d2 9c 02 06 8f ?? 00 00 01 25 47 20 91 00 00 00 59 d2 52 02 06 8f ?? 00 00 01 25 47 1f 46 58 d2 52 00 06 17 58 0a 06 02 8e 69 fe 04 0b 07 2d c9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AIIA_2147930033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AIIA!MTB"
        threat_id = "2147930033"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 13 04 11 04 09 06 07 6f ?? 00 00 0a 17 73 2a 00 00 0a 13 05 11 05 08 16 08 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 06 dd}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_MBWM_2147930099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.MBWM!MTB"
        threat_id = "2147930099"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {9c 07 08 04 08 05 5d 91 9c 08 17 58 0c 08 20 00 01 00 00}  //weight: 1, accuracy: High
        $x_2_2 = {49 39 55 64 6a 77 44 00 44 51 6a 62 43 67 64 44 61 4d 4d 56 4e 64 45 47 4b 6b}  //weight: 2, accuracy: High
        $x_2_3 = {47 33 44 77 64 32 33 00 6c 6c 78 69 4f 39 4d 6a 72 41 49 6d 77 63 68 68 4f 65}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_LummaC_ARIA_2147930712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.ARIA!MTB"
        threat_id = "2147930712"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {38 a3 00 00 00 2b 3c 72 ?? 00 00 70 2b 38 2b 3d 2b 42 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 1a 2c 1d 08 6f ?? 00 00 0a 0d 28 ?? 00 00 0a 09 07 16 07 8e 69 6f ?? 00 00 0a 6f ?? 00 00 0a 0a de 1e}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_ALC_2147930765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.ALC!MTB"
        threat_id = "2147930765"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 08 91 06 09 91 58 20 00 01 00 00 5d 13 06 02 11 05 8f 1e 00 00 01 25 47 06 11 06 91 61 d2 52 11 05 17 58 13 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_ALC_2147930765_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.ALC!MTB"
        threat_id = "2147930765"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 58 11 31 5d 13 2f 11 30 11 2d 11 2f 91 58 11 31 5d 13 30 73 1a 00 00 0a 13 66 11 66 11 2d 11 30 91 6f ?? 00 00 0a 11 2d 11 30 11 2d 11 2f 91 9c 11 2d 11 2f 11 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_ALC_2147930765_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.ALC!MTB"
        threat_id = "2147930765"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5d 13 2f 11 30 11 2d 11 2f 91 58 28 ?? 00 00 0a 11 31 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 5d 13 30 73 28 00 00 0a 13 34 11 34 11 2d 11 30 91 6f ?? 00 00 0a 11 2d 11 30 11 2d 11 2f 91 9c 11}  //weight: 2, accuracy: Low
        $x_1_2 = {0d 13 04 16 13 05 2b 20 11 04 11 05 91 13 06 09 72 ?? 00 00 70 11 06 8c ?? 00 00 01 6f ?? 00 00 0a 26 11 05 17 58 13 05 11 05 11 04 8e 69 32 d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AYA_2147930963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AYA!MTB"
        threat_id = "2147930963"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "$ab382339-c29b-4560-af26-a0ff9718742e" ascii //weight: 3
        $x_1_2 = "testreverseproxy" ascii //weight: 1
        $x_1_3 = "AddFolderToDefenderExclusions" ascii //weight: 1
        $x_1_4 = "GenerateRandomFileName" ascii //weight: 1
        $x_1_5 = "GenerateRandomFolderName" ascii //weight: 1
        $x_1_6 = "IsRunAsAdmin" ascii //weight: 1
        $x_1_7 = "RestartAsAdmin" ascii //weight: 1
        $x_1_8 = "Command \"Add-MpPreference -ExclusionPath" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AMCS_2147930982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AMCS!MTB"
        threat_id = "2147930982"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 01 11 01 16 11 01 8e 69 6f ?? 00 00 0a 13 05 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AMCZ_2147930988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AMCZ!MTB"
        threat_id = "2147930988"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {5d 0c 09 06 08 91 58 20 00 01 00 00 5d 0d 06 09 91 13 07 06 09 06 08 91 9c 06 08 11 07 9c}  //weight: 4, accuracy: High
        $x_1_2 = {06 08 08 28 ?? 00 00 0a 9c 07 08 04 08 05 5d 91 9c 08 17 58 0c 08 20 00 01 00 00 3f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_GNT_2147931311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.GNT!MTB"
        threat_id = "2147931311"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {a2 a2 14 13 03 12 03 28 ?? ?? ?? 06 28 ?? ?? ?? 06 13 00 20 01 00 00 00 28 ?? ?? ?? 06 3a ?? ?? ?? ?? 26 38 ?? ?? ?? ?? 00 20 30 75 00 00 28 ?? ?? ?? 0a 38}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_GNT_2147931311_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.GNT!MTB"
        threat_id = "2147931311"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 2f 17 58 28 ?? ?? ?? 0a 11 31 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 5d 13 2f 11 30 11 2d 11 2f 91 58 28 ?? ?? ?? 0a 11 31 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 5d 13 30 73 ?? ?? ?? ?? 13 34 11 34 11 2d 11 30 91 6f ?? ?? ?? 0a 11 2d 11 30 11 2d 11 2f 91 9c 11 2d 11 2f 11 34 16 6f ?? ?? ?? 0a 9c 11 2d 11 2f 91 11 2d 11 30 91 58 28 ?? ?? ?? 0a 11 31 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 5d 13 35 73 ?? ?? ?? ?? 13 36 11 36 11 2d 11 35 91 6f ?? ?? ?? 0a 73 ?? ?? ?? ?? 13 37 11 37 11 33 6f ?? ?? ?? 0a 73 ?? ?? ?? ?? 72 3f 00 00 70 11 37 6f ?? ?? ?? 0a 13 39 12 39 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 06 16 13 38 02 11 33 91 13 38 11 38 11 36 16 6f ?? ?? ?? 0a 61 d2 13 38 02 11 33 11 38 9c 11 33 17 58 13 33 11 33 03}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AMDC_2147931540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AMDC!MTB"
        threat_id = "2147931540"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 11 30 8f ?? 00 00 01 25 47 11 33 16 6f ?? 00 00 0a 61 d2 52 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_BK_2147931610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.BK!MTB"
        threat_id = "2147931610"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 2b 11 2d 91 11 2b 11 2e 91 58 28 ?? 00 00 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 5d 13 32}  //weight: 3, accuracy: Low
        $x_2_2 = {01 25 47 11 34 16 6f ?? 00 00 0a 61 d2 52 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AWJA_2147931898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AWJA!MTB"
        threat_id = "2147931898"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {02 11 30 8f ?? 00 00 01 25 47 11 33 16 6f ?? 00 00 0a 61 d2 52 38}  //weight: 4, accuracy: Low
        $x_2_2 = {11 2d 17 58 28 ?? 00 00 0a 72 f8 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 5d 13 2d 38}  //weight: 2, accuracy: Low
        $x_2_3 = {11 2e 11 2b 11 2d 91 58 28 ?? 00 00 0a 72 f8 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 5d 13 2e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_NLI_2147931916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.NLI!MTB"
        threat_id = "2147931916"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {25 47 11 33 16 ?? ?? 00 00 0a 61 d2 52}  //weight: 2, accuracy: Low
        $x_1_2 = {11 25 11 1b 61 13 0e ?? ?? ?? ?? ?? 16 13 2e}  //weight: 1, accuracy: Low
        $x_1_3 = "ac049bfa-2dd8-4f1a-9314-11e3fed61454" ascii //weight: 1
        $x_1_4 = "kLjw4iIsCLsZtxc4lksN0j" ascii //weight: 1
        $x_1_5 = "CreateEncryptor" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_SEE_2147931945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.SEE!MTB"
        threat_id = "2147931945"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 01 11 08 1e 6f 29 00 00 0a 17 8d 2c 00 00 01 6f 2a 00 00 0a 28 0e 00 00 06 28 1b 00 00 0a 72 ?? ?? ?? 70 28 2b 00 00 0a 6f 2c 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {11 00 28 24 00 00 0a 13 01 38 f4 01 00 00 fe 0c 06 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AMDE_2147931987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AMDE!MTB"
        threat_id = "2147931987"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 25 47 11 ?? 16 6f ?? 00 00 0a 61 d2 52 20 ?? 00 00 00 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_BL_2147932237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.BL!MTB"
        threat_id = "2147932237"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 2d 17 58 7e ?? 00 00 04 28 ?? 00 00 06 11 2f 7e ?? 00 00 04 28 ?? 00 00 06 7e ?? 00 00 04 28 ?? 00 00 06 7e ?? 00 00 04 28 ?? 00 00 06 5d}  //weight: 3, accuracy: Low
        $x_2_2 = {02 11 31 8f ?? 00 00 01 25 47 11 35 16 6f ?? 00 00 0a 61 d2 52 38}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_BL_2147932237_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.BL!MTB"
        threat_id = "2147932237"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0b 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 06 08 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0d 02 28 ?? 00 00 0a 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 05 28 ?? 00 00 0a 11 05 6f ?? 00 00 0a 13 06 de}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AMDF_2147932288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AMDF!MTB"
        threat_id = "2147932288"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 25 47 11 ?? 16 6f ?? 00 00 0a 61 d2 52 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AMDG_2147932480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AMDG!MTB"
        threat_id = "2147932480"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 25 47 11 ?? 16 6f ?? 00 00 0a 61 d2 52 11 ?? 17 58 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_BB_2147932666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.BB!MTB"
        threat_id = "2147932666"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {11 2e 11 2b 11 2d 91 58 11 2c 11 2d 91 58 20 00 01 00 00 5d 13 2e 11 2b 11 2e 91 13 2f 11 2b 11 2e 11 2b 11 2d 91 9c 11 2b 11 2d 11 2f 9c 11 2d 17 58 13 2d 11 2d 20 00 01 00 00 3f c0 ff ff ff}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AMKA_2147932702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AMKA!MTB"
        threat_id = "2147932702"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 36 11 34 16 6f ?? 00 00 0a 61 d2 13 36 20}  //weight: 3, accuracy: Low
        $x_2_2 = {02 11 31 11 36 9c 20}  //weight: 2, accuracy: High
        $x_2_3 = {11 2d 17 58 7e ?? 00 00 04 28 ?? 01 00 06 11 2f 7e ?? 00 00 04 28 ?? 01 00 06 7e ?? 00 00 04 28 ?? 01 00 06 7e ?? 00 00 04 28 ?? 01 00 06 5d 13 2d 38 ?? ?? 00 00 11 35 11 31 6f ?? 00 00 0a 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_ATKA_2147932921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.ATKA!MTB"
        threat_id = "2147932921"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 36 11 34 16 6f ?? 00 00 0a 61 d2 13 36 38}  //weight: 3, accuracy: Low
        $x_2_2 = {11 2b 11 2d 91 11 2b 11 2e 91 58 7e ?? 01 00 04 28 ?? 03 00 06 11 2f 7e ?? 01 00 04 28 ?? 04 00 06 7e ?? 01 00 04 28 ?? 04 00 06 7e ?? 01 00 04 28 ?? 04 00 06 5d 13 33 38}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AUKA_2147932936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AUKA!MTB"
        threat_id = "2147932936"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {16 13 36 02 11 31 91 13 36 11 36 11 34 16 6f ?? 00 00 0a 61 d2 13 36 02 11 31 11 36 9c 11 31 17 58 13 31}  //weight: 3, accuracy: Low
        $x_2_2 = {11 2d 17 58 28 ?? 00 00 0a 11 2f 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 5d 13 2d 11 2e 11 2b 11 2d 91 58 28 ?? 00 00 0a 11 2f 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 5d 13 2e 73 29 00 00 0a 13 32 11 32 11 2b 11 2e 91 6f ?? 00 00 0a 11 2b 11 2e 11 2b 11 2d 91 9c 11 2b 11 2d 11 32 16}  //weight: 2, accuracy: Low
        $x_1_3 = "eATNPsJxmh8mp7aUYd" ascii //weight: 1
        $x_1_4 = "eRtoUikQAUlfmrcXhP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_SPYF_2147933403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.SPYF!MTB"
        threat_id = "2147933403"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 38 11 36 16 6f ?? 00 00 0a 61 d2 13 38 38 24 00 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = {11 2e 11 2f 04 11 2f 05 5d 91 9c 20 04 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AAC_2147933648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AAC!MTB"
        threat_id = "2147933648"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 16 13 37 02 11 33 91 13 37 11 37 11 36 16 6f ?? 00 00 0a 61 d2 13 37 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AVLA_2147933794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AVLA!MTB"
        threat_id = "2147933794"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 34 11 34 11 2d 11 30 91 6f ?? 00 00 0a 11 2d 11 30 11 2d 11 2f 91 9c 11 2d 11 2f 11 34 16 6f ?? 00 00 0a 9c 11 2d 11 2f 91 11 2d 11 30 91 58 28 ?? 00 00 0a 11 31 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 5d 13 35 73 ?? 00 00 0a 13 36 11 36 11 2d 11 35 91 6f ?? 00 00 0a 73 ?? 00 00 0a 11 33 6f ?? 00 00 0a 16 13 37 02 11 33 91 13 37 11 37 11 36 16 6f ?? 00 00 0a 61 d2 13 37 02 11 33 11 37 9c 11 33 17 58 13 33}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_SYFD_2147933906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.SYFD!MTB"
        threat_id = "2147933906"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 37 11 36 16 6f ?? 00 00 0a 61 d2 13 37 02 11 33 11 37 9c 11 33 17 58 13 33}  //weight: 2, accuracy: Low
        $x_1_2 = {91 11 2d 11 30 91 58 28 ?? 00 00 0a 11 31 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 5d 13 35 73 ?? 00 00 0a 13 36 11 36 11 2d 11 35 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AYLA_2147933921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AYLA!MTB"
        threat_id = "2147933921"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 08 9a 28 ?? 00 00 0a 03 08 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 0d 09 59 08 1f 0c 5d 59 20 00 01 00 00 58 20 00 01 00 00 5d d1 13 04 07 11 04 6f ?? 00 00 0a 26 08 17 58 0c 08 06 8e 69 32 c0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_SAT_2147934102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.SAT!MTB"
        threat_id = "2147934102"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 0a 00 00 04 28 01 00 00 2b 7e ?? ?? ?? 04 25 3a 17 00 00 00 26 7e ?? ?? ?? 04 fe 06 16 00 00 06 73 33 00 00 0a 25 80 ?? ?? ?? 04 28 02 00 00 2b 28 03 00 00 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_BN_2147934240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.BN!MTB"
        threat_id = "2147934240"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {61 d2 13 69 02 11 65 11 69 9c 11 65 17 58 13 65 11 65 03}  //weight: 3, accuracy: High
        $x_2_2 = {17 58 11 31 5d 13 2f 11 30 11 2d 11 2f 91 58 11 31 5d 13 30 73 ?? 00 00 0a 13 66 11 66 11 2d 11 30 91}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_EABD_2147934440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.EABD!MTB"
        threat_id = "2147934440"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {fe 0e 29 00 20 81 4a 85 0b 20 04 c0 3e 0d 58 20 6b 2f b0 4a 61 fe 0e 2a 00 fe 0c 26 00 fe 0c 26 00 20 05 00 00 00 62 61 fe 0e 26 00 fe 0c 26 00 fe 0c 28 00 58 fe 0e 26 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_GPPG_2147934846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.GPPG!MTB"
        threat_id = "2147934846"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {11 2b 11 07 59 13 14 38 05 fd ff ff 11 26 11 13 61 13 0e}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_GPPG_2147934846_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.GPPG!MTB"
        threat_id = "2147934846"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {11 0e 6e 11 29 6a 31 0d 11 26 11 13 61 13 0e 11 0d 11 1c 5b 26 16 13 2f 16 13 30 2b 34}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_ARMA_2147934875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.ARMA!MTB"
        threat_id = "2147934875"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 69 11 68 16 6f ?? 00 00 0a 61 d2 13 69 38}  //weight: 3, accuracy: Low
        $x_2_2 = {11 30 11 2d 11 2f 91 58 11 2e 11 2f 91 58 20 00 01 00 00 5d 13 30}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AUMA_2147934968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AUMA!MTB"
        threat_id = "2147934968"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 69 11 68 16 6f ?? 00 00 0a 61 d2 13 69 02 11 69 8c ?? 00 00 01 11 65 6f ?? 00 00 0a 11 65 17 58 13 65}  //weight: 3, accuracy: Low
        $x_2_2 = {11 2f 17 58 11 31 5d 13 2f 11 30 11 2d 11 2f 91 58 11 31 5d 13 30 73 ?? 00 00 0a 13 66 11 66 11 2d 11 30 91 6f ?? 00 00 0a 11 2d 11 30 11 2d 11 2f 91 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AAH_2147935105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AAH!MTB"
        threat_id = "2147935105"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 2f 17 58 11 31 5d 13 2f 11 30 11 2d 11 2f 91 58}  //weight: 1, accuracy: High
        $x_4_2 = {11 9d 11 9c 16 6f ?? 00 00 0a 61 d2 13 9d 11 73 11 72 31 10}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AFNA_2147935297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AFNA!MTB"
        threat_id = "2147935297"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 9a 11 99 16 6f ?? 00 00 0a 61 d2 13 9a 02 11 65 11 9a 9c 11 65 17 58 13 65}  //weight: 3, accuracy: Low
        $x_2_2 = {11 2f 17 58 11 31 5d 13 2f 11 30 11 2d 11 2f 91 58 11 31 5d 13 30 73 ?? 00 00 0a 13 66 11 66 11 2d 11 30 91}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_ALNA_2147935547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.ALNA!MTB"
        threat_id = "2147935547"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 36 11 35 16 6f ?? 00 00 0a 61 d2 13 36 02 11 32 11 36 9c 11 32 17 58 13 32 11 32 03 3f}  //weight: 3, accuracy: Low
        $x_2_2 = {11 30 11 2d 11 2f 91 58 20 00 01 00 00 5d 13 30 73 ?? 00 00 0a 13 33 11 33 11 2d 11 30 91 6f ?? 00 00 0a 11 2d 11 30 11 2d 11 2f 91 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_SWA_2147935627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.SWA!MTB"
        threat_id = "2147935627"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1f 24 8d 15 00 00 01 25 d0 06 00 00 04 28 11 00 00 0a 80 02 00 00 04 20 4b 05 00 00 8d 15 00 00 01 25 d0 07 00 00 04 28 11 00 00 0a 80 03 00 00 04 14 80 04 00 00 04 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_SWB_2147935628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.SWB!MTB"
        threat_id = "2147935628"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 11 07 1f 28 5a 58 13 08 28 1e 00 00 0a 07 11 08 1e 6f 1f 00 00 0a 17 8d 20 00 00 01 6f 20 00 00 0a 13 09 11 09 72 01 00 00 70 28 21 00 00 0a 2c 3e 07 11 08 1f 14 58 28 1d 00 00 0a 13 0a 07 11 08 1f 10 58 28 1d 00 00 0a 13 0b 11 0b 8d 17 00 00 01 80 04 00 00 04 07 11 0a 6e 7e 04 00 00 04 16 6a 11 0b 6e 28 22 00 00 0a 17 13 06 de 31 de 21 25 6f 23 00 00 0a 28 24 00 00 0a 6f 23 00 00 0a 25 2d 06 26 72 0b 00 00 70 28 25 00 00 0a 26 de 00 11 07 17 58 13 07 11 07 09 3f 5e ff ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_SWC_2147935631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.SWC!MTB"
        threat_id = "2147935631"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1f 24 8d 17 00 00 01 25 d0 06 00 00 04 28 ?? 00 00 0a 80 02 00 00 04 20 4b 05 00 00 8d 17 00 00 01 25 d0 07 00 00 04 28 ?? 00 00 0a 80 03 00 00 04 14 80 04 00 00 04 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_EAEE_2147935741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.EAEE!MTB"
        threat_id = "2147935741"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 2f 17 58 28 14 00 00 0a 11 31 28 15 00 00 0a 6f 16 00 00 0a 28 17 00 00 0a 5d 13 2f 11 30 11 2d 11 2f 91 58 28 14 00 00 0a 11 31 28 15 00 00 0a 6f 16 00 00 0a 28 17 00 00 0a 5d 13 30 73 18 00 00 0a 13 34 11 34 11 2d 11 30 91 6f 19 00 00 0a 11 2d 11 30 11 2d 11 2f 91 9c 11 2d 11 2f 11 34 16 6f 1a 00 00 0a 9c 11 2d 11 2f 91}  //weight: 5, accuracy: High
        $x_5_2 = {11 2d 11 30 91 58 28 14 00 00 0a 11 31 28 15 00 00 0a 6f 16 00 00 0a 28 17 00 00 0a 5d 13 35 73 18 00 00 0a 13 36 11 36 11 2d 11 35 91 6f 19 00 00 0a 73 1b 00 00 0a 11 33 6f 1c 00 00 0a 16 13 37 02 11 33 91 13 37 de 0a 26 11 37 28 1d 00 00 0a de 00 11 37 11 36 16 6f 1a 00 00 0a 61 d2 13 37 02 11 33 11 37 9c 11 33 17 58 13 33 11 33 03 3f 1e ff ff ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_EAEQ_2147935745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.EAEQ!MTB"
        threat_id = "2147935745"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {28 02 00 00 06 0c 72 61 00 00 70 28 01 00 00 0a 0d 72 93 00 00 70 28 01 00 00 0a 13 04 73 02 00 00 0a 13 05 73 03 00 00 0a 13 06 11 06 11 05 09 11 04 6f 04 00 00 0a 17 73 05 00 00 0a 13 07}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_EAHG_2147936228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.EAHG!MTB"
        threat_id = "2147936228"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 0d 28 64 00 00 06 13 17 11 0d 6f 9a 00 00 06 13 18 11 04 11 17 11 18 6f 4d 00 00 0a 11 16 17 58 13 16 11 16 11 0c 3f d4 ff ff ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AKOA_2147936358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AKOA!MTB"
        threat_id = "2147936358"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {17 2c 06 14 38 bb 00 00 00 72 ?? ?? 00 70 38 b7 00 00 00 38 bc 00 00 00 72 ?? ?? 00 70 38 b8 00 00 00 38 bd 00 00 00 38 be 00 00 00 1d 3a c2 00 00 00 26 2b 70 38 71 00 00 00 08 6f ?? ?? 00 0a 13 04 73 ?? ?? 00 0a 13 05 11 05 11 04 17 73 ?? ?? 00 0a 13 06 16 2d 11 2b 0f 19 2c 1e 00 28 ?? 00 00 06 0a de 03 26 de 00 19 2c 0f 06 2c eb 11 06 06 16 06 8e 69 6f ?? ?? 00 0a 11 05 6f ?? ?? 00 0a 0a de 1b}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_GTZ_2147936428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.GTZ!MTB"
        threat_id = "2147936428"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 37 1d 11 0d 5f 91 13 1f 11 1f 19 62 11 1f 1b 63 60 d2 13 1f 11 05 11 0d 11 05 11 0d 91 11 1f 61 d2 9c 11 0d 17 58 13 0d 11 0d 11 07 32 d1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_SWD_2147936849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.SWD!MTB"
        threat_id = "2147936849"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 87 00 00 06 1f 24 8d 1e 00 00 01 25 d0 07 00 00 04 28 17 00 00 0a 80 03 00 00 04 20 4b 05 00 00 8d 1e 00 00 01 25 d0 08 00 00 04 28 17 00 00 0a 80 04 00 00 04 14 80 05 00 00 04 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_NMB_2147936878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.NMB!MTB"
        threat_id = "2147936878"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" ascii //weight: 1
        $x_2_2 = {02 11 15 9a 12 17 28 0e 01 00 0a 3a 4a 01 00 00 11 13 2c 0a 11 05 11 13}  //weight: 2, accuracy: High
        $x_1_3 = "script.ps1" ascii //weight: 1
        $x_1_4 = {a2 11 22 18 72 fc 03 00 70 a2 11 22 19 11 12 a2 11 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_LAT_2147938690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.LAT!MTB"
        threat_id = "2147938690"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 14 72 91 48 00 70 16 8d 01 00 00 01 14 14 14 28 ?? 00 00 0a 20 b6 fe 0d 00 8c 88 00 00 01 28 ?? 01 00 0a 17 8c 88 00 00 01 28 ?? 01 00 0a 28 ?? 00 00 0a 80 0b 00 00 04 03 74 8a 00 00 1b 20 b6 fe 0d 00 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 07 0a 2b 00 06 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_EAAN_2147939206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.EAAN!MTB"
        threat_id = "2147939206"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 30 11 2d 11 2f 91 58 11 2e 11 2f 91 58 20 00 01 00 00 5d 13 30 11 2d 11 30 91 13 32 11 2d 11 30 11 2d 11 2f 91 9c 11 2d 11 2f 11 32 9c 11 2f 17 58 13 2f 11 2f 20 00 01 00 00 32 c3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_GTM_2147939354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.GTM!MTB"
        threat_id = "2147939354"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 05 11 05 08 28 ?? 15 00 06 11 05 09 28 ?? 15 00 06 11 04 11 05 6f ?? 09 00 0a 17 73 ?? ?? ?? 0a 13 06 11 06 07 16 07 8e 69 6f ?? 08 00 0a 11 06 28 ?? 15 00 06 11 04 6f ?? 09 00 0a 28 ?? 09 00 0a 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_BS_2147940690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.BS!MTB"
        threat_id = "2147940690"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {03 59 11 01 59 20 ff 00 00 00 5f d2}  //weight: 3, accuracy: High
        $x_1_2 = {02 11 01 91 13}  //weight: 1, accuracy: High
        $x_1_3 = {02 03 1f 1f 5f 63 02 1e 03 59 1f 1f 5f 62 60 d2 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

