rule Trojan_MSIL_DarkNeuron_B_2147724727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkNeuron.B!dha"
        threat_id = "2147724727"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkNeuron"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "BSJB" ascii //weight: 20
        $x_1_2 = "MSExchangeService" ascii //weight: 1
        $x_1_3 = "cadataKey" wide //weight: 1
        $x_1_4 = "cid" wide //weight: 1
        $x_1_5 = "cadata" wide //weight: 1
        $x_1_6 = "cadataSig" wide //weight: 1
        $x_1_7 = "PFJTQUtleVZhbHVlPjxNb2R1bHVzPnZ3WXRKcnNRZjVTcCtWVG9Rb2xuaEVkMHVwWDFrVElFTUNTN" wide //weight: 1
        $x_1_8 = "EFnRkRCclNmclpKS0owN3BYYjh2b2FxdUtseXF2RzBJcHV0YXhDMVRYazRoeFNrdEpzbHljU3RFaHBUc1l" wide //weight: 1
        $x_1_9 = "4OVBEcURabVVZVklVbHlwSFN1K3ljWUJWVFdubTZmN0JTNW1pYnM0UWhMZElRbnl1ajFMQyt6TUh" wide //weight: 1
        $x_1_10 = "wZ0xmdEc2b1d5b0hyd1ZNaz08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjwvUlNBS2V5VmFsdWU+" wide //weight: 1
        $x_1_11 = "ZmlyZWZveCxjaHJvbWUsb3BlcmEsYWJieSxtb3ppbGxhLGdvb2dsZSxoZXdsZXQsZXBzb24seGVyb3gscmljb2gsYWRvYmUs" wide //weight: 1
        $x_1_12 = "Y29yZWwsamF2YSxudmlkaWEscmVhbHRlayxvcmFjbGUsd2lucmFyLDd6aXAsdm13YXJlLGp1bmlwZXIsa2FzcGVyc2t5LG1j" wide //weight: 1
        $x_1_13 = "8d963325-01b8-4671-8e82-d0904275ab06" wide //weight: 1
        $x_1_14 = "MSXEWS" wide //weight: 1
        $x_1_15 = "443/ews/exchange/" wide //weight: 1
        $x_1_16 = "U09GVFdBUkVcTWljcm9zb2Z0XENyeXB0b2dyYXBo" wide //weight: 1
        $x_1_17 = "neuron_service" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_DarkNeuron_C_2147724728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkNeuron.C!dha"
        threat_id = "2147724728"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkNeuron"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "BSJB" ascii //weight: 20
        $x_1_2 = {eb 07 3d 15 12 31 01 12 34 08 0e 12 81 8d 1d 05 12 81 31 1d 12 81 21 1d 12 81 21 1d 12 81 21 08 1d 12 81 21 1d 12 81 21 1d 12}  //weight: 1, accuracy: High
        $x_1_3 = {81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21}  //weight: 1, accuracy: High
        $x_1_4 = {1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkNeuron_D_2147724729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkNeuron.D!dha"
        threat_id = "2147724729"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkNeuron"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 6f 6d 6d 61 ?? 64 53 63 72 69 70 74}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 53 45 78 63 68 61 6e ?? 65 53 65 72 76 69 63 65}  //weight: 1, accuracy: Low
        $x_1_3 = {57 33 57 50 44 ?? 41 47}  //weight: 1, accuracy: Low
        $x_1_4 = {41 64 64 43 6f 6e 66 ?? 67 41 73 53 74 72 69 6e 67}  //weight: 1, accuracy: Low
        $x_1_5 = {44 65 6c 43 6f 6e 66 69 67 41 73 53 ?? 72 69 6e 67}  //weight: 1, accuracy: Low
        $x_1_6 = {45 6e 63 72 79 70 74 53 63 ?? 69 70 74}  //weight: 1, accuracy: Low
        $x_1_7 = {45 78 65 63 43 ?? 44}  //weight: 1, accuracy: Low
        $x_1_8 = {4b 69 6c 6c 4f 6c 64 54 ?? 72 65 61 64}  //weight: 1, accuracy: Low
        $x_1_9 = {46 69 6e 64 53 50 ?? 74 68}  //weight: 1, accuracy: Low
        $x_1_10 = {43 6f 6d 6d 61 6e 64 54 69 ?? 65 57 61 69 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

