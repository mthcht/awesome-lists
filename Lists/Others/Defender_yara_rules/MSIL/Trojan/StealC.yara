rule Trojan_MSIL_StealC_CCES_2147897712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.CCES!MTB"
        threat_id = "2147897712"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 0c 08 16 2f 08 08 20 ?? ?? ?? ?? 58 0c 06 07 08 d1 9d 07 17 58 0b 07 02 6f ?? 00 00 0a 32 d2}  //weight: 1, accuracy: Low
        $x_1_2 = {02 07 91 0c 03 07 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a d2 0d 08 09 28 ?? 01 00 06 13 04 06 07 11 04 9c 00 07 17 58 0b 07 02 8e 69 fe 04 13 05 11 05 2d cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_ASA_2147898581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.ASA!MTB"
        threat_id = "2147898581"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 da 0b 16 0c 2b 15 02 08 02 08 9a 03 72 3b 00 00 70 6f 42 00 00 0a a2 08 17 d6 0c 08 07 31 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_RDE_2147902137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.RDE!MTB"
        threat_id = "2147902137"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 59 09 59 20 00 01 00 00 5d 13 04 11 04 16}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_A_2147902946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.A!MTB"
        threat_id = "2147902946"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 0b 07 8e 69 1f ?? 28 ?? ?? 00 06 2e ?? 08 15 31 ?? 07 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 28 ?? ?? 00 06 07 28 ?? ?? 00 06 0d 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_AE_2147903599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.AE!MTB"
        threat_id = "2147903599"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 05 07 6f ?? ?? ?? 0a 8c 29 00 00 01 28 ?? ?? ?? 0a 0a 07 17 59 0b 07 16 3c e2 ff ff ff 06}  //weight: 1, accuracy: Low
        $x_1_2 = "Displacement.exe" ascii //weight: 1
        $x_1_3 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_NB_2147905368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.NB!MTB"
        threat_id = "2147905368"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {59 93 61 11 0b ?? 2c 00 00 1b 11 09 11 0c 58}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_NB_2147905368_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.NB!MTB"
        threat_id = "2147905368"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {7e 0e 00 00 04 16 fe 06 ?? 00 00 06 9b 16 2d e5 7e ?? 00 00 04 17 fe 06 ?? 00 00 06 9b 16 2d e0}  //weight: 3, accuracy: Low
        $x_3_2 = {8d 37 00 00 01 80 ?? 00 00 04 7e ?? 00 00 04 16 fe 06 ?? 00 00 06 9b 7e 0b 00 00 04 17 fe 06 ?? 00 00 06 9b 7e ?? 00 00 04 18 fe 06 ?? 00 00 06 9b}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_NC_2147906791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.NC!MTB"
        threat_id = "2147906791"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {1a 13 0b 2b dc 08 6f 23 00 00 0a 1e 5b 8d 0f 00 00 01 13 05 17 13 0b 2b c8 07 1e 11 05 16 1e 28 ?? 00 00 0a 19}  //weight: 3, accuracy: Low
        $x_3_2 = {13 0b 2b b8 73 ?? 00 00 0a 13 06 1b 13 0b 2b ac 00 18 13 0b}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_NC_2147906791_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.NC!MTB"
        threat_id = "2147906791"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {02 03 02 4b 03 04 5f 03 66 05 5f 60 58 0e 07 0e 04 e0 95 58 7e 70 19 00 04 0e 06 17 59 e0 95 58 0e 05}  //weight: 3, accuracy: High
        $x_2_2 = "69fc8618-d6a2-4930-9b87-8efcfdee5cf2" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_KAF_2147907245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.KAF!MTB"
        threat_id = "2147907245"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 06 09 93 07 09 07 8e 69 5d 93 59 20 00 01 00 00 59 20 00 01 00 00 5d 13 04 11 04 16 fe 04 13 05 11 05 2c 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_B_2147907785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.B!MTB"
        threat_id = "2147907785"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0b 11 0c 58 11 06 11 0c 91 52 11 0c 17 58 13 0c 11 0c 11 06 8e 69}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_NS_2147907897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.NS!MTB"
        threat_id = "2147907897"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 37 00 00 01 25 d0 36 00 00 04 28 ?? 00 00 0a 6f d6 00 00 0a}  //weight: 3, accuracy: Low
        $x_3_2 = {07 1f 10 8d 37 00 00 01 25 d0 37 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 06 07 6f d8 00 00 0a}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_RDF_2147908240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.RDF!MTB"
        threat_id = "2147908240"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 28 58 00 00 06 28 5a 00 00 06 6f 33 00 00 0a 02 16 02 8e 69 6f 34 00 00 0a 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_NL_2147908451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.NL!MTB"
        threat_id = "2147908451"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 21 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 6f 0c 01 00 0a 07 1f 10 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 6f ?? 01 00 0a 06 07 6f ?? 01 00 0a 17}  //weight: 5, accuracy: Low
        $x_1_2 = "openshock.Properties.Resources" ascii //weight: 1
        $x_1_3 = "SplittyDev" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_NM_2147909804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.NM!MTB"
        threat_id = "2147909804"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 11 02 6f ?? 00 00 0a 20 ?? 00 00 00 28 ?? 00 00 06 39 ?? ff ff ff 26 38}  //weight: 5, accuracy: Low
        $x_1_2 = "industrialcustomtour" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_CCIG_2147911410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.CCIG!MTB"
        threat_id = "2147911410"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 07 17 73 ?? ?? ?? ?? 0d 00 09 03 16 03 8e 69 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 00 00 de 0b 09 2c 07 09 6f ?? 00 00 0a 00 dc 08 6f ?? 00 00 0a 13 04 de 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_CCJB_2147917340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.CCJB!MTB"
        threat_id = "2147917340"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 08 07 08 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 00 08 07 08 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 00 73 ?? ?? ?? ?? 0d 09 08 6f ?? 00 00 0a 17 73 ?? ?? ?? ?? 13 04 11 04 02 16 02 8e 69 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 13 05 11 05 13 06 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_KAG_2147918532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.KAG!MTB"
        threat_id = "2147918532"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 11 22 91 61 d2 81 ?? 00 00 01 11 08 17 58 13 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_MBXN_2147918548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.MBXN!MTB"
        threat_id = "2147918548"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 9d b6 29 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00}  //weight: 2, accuracy: High
        $x_1_2 = "GetPixel" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = ".g.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_KAH_2147918744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.KAH!MTB"
        threat_id = "2147918744"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 11 21 91 61 d2 81 ?? 00 00 01 11 07 17 58 13 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_RDH_2147918932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.RDH!MTB"
        threat_id = "2147918932"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 11 13 8f 13 00 00 01 25 71 13 00 00 01 06 11 26 91 61 d2 81 13 00 00 01 11 13 17 58 13 13 11 13 02 8e 69}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_KAJ_2147919017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.KAJ!MTB"
        threat_id = "2147919017"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 13 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 28 91 61 d2 81 ?? 00 00 01 11 13 17 58}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_EZ_2147921605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.EZ!MTB"
        threat_id = "2147921605"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Gastraea Bouillons Redresses" ascii //weight: 2
        $x_2_2 = "Siphonages Apomorphine Paraforms" ascii //weight: 2
        $x_2_3 = "375c5eff-0650-4301-85ef-382cfefa9adf" ascii //weight: 2
        $x_1_4 = "AIOsncoiuuA" ascii //weight: 1
        $x_1_5 = "ioAHsiujxhbiAIkao" ascii //weight: 1
        $x_1_6 = "VQP.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_AYA_2147922987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.AYA!MTB"
        threat_id = "2147922987"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BazaidBOtNet" wide //weight: 2
        $x_1_2 = "$cb2aae6e-4e03-41f7-b9d1-1b89e8b1cf22" ascii //weight: 1
        $x_1_3 = "CryptoObfuscator_Output" ascii //weight: 1
        $x_1_4 = "U3R1YlN0dWI=" wide //weight: 1
        $x_1_5 = "Stub.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_AYA_2147922987_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.AYA!MTB"
        threat_id = "2147922987"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$ee97d652-504f-4da6-a6e2-26bd773bc3c3" ascii //weight: 2
        $x_1_2 = "QCXBSDJHIUWE643.pdb" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_SAM_2147934105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.SAM!MTB"
        threat_id = "2147934105"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 2d 01 00 04 28 40 03 00 06 28 25 00 00 0a 0a 06 28 26 00 00 0a 0b 07 16}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_SF_2147940857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.SF!MTB"
        threat_id = "2147940857"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 d1 13 10 11 1f 11 09 91 13 28 11 1f 11 09 11 28 11 27 61 11 1c 19 58 61 11 32 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_IVBN_2147948765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.IVBN!MTB"
        threat_id = "2147948765"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 1b 12 02 28 ?? 01 00 0a 0d 07 09 28 ?? 01 00 0a 28 ?? 01 00 0a 28 ?? 00 00 0a 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealC_SLBB_2147951007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealC.SLBB!MTB"
        threat_id = "2147951007"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 04 1c 28 14 00 00 0a 09 28 07 00 00 06 11 04 28 07 00 00 06 28 15 00 00 0a 6f 16 00 00 0a 28 04 00 00 06 09 08 28 05 00 00 06 73 17 00 00 0a 25 72 d1 00 00 70 6f 18 00 00 0a 25 72 e1 00 00 70 09 72 fd 00 00 70}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

