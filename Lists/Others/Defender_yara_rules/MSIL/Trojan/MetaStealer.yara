rule Trojan_MSIL_MetaStealer_DA_2147816375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MetaStealer.DA!MTB"
        threat_id = "2147816375"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MetaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {01 57 bf a3 3f 09 0f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 e3 00 00 00 fc 00 00 00 f3 01}  //weight: 3, accuracy: High
        $x_3_2 = "SymmetricAlgorithm" ascii //weight: 3
        $x_3_3 = "System.Security.Cryptography" ascii //weight: 3
        $x_3_4 = "MulticastDelegate" ascii //weight: 3
        $x_3_5 = "set_UseShellExecute" ascii //weight: 3
        $x_3_6 = "{11111-22222-10009-11111}" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MetaStealer_NB_2147904135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MetaStealer.NB!MTB"
        threat_id = "2147904135"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MetaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {25 06 93 0b 06 18 58 93 07 61 0b 17 13 0e 2b 80}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MetaStealer_KMAA_2147907630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MetaStealer.KMAA!MTB"
        threat_id = "2147907630"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MetaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 05 11 01 91 11 05 11 02 91 58 20 00 01 00 00 5d}  //weight: 2, accuracy: High
        $x_2_2 = {03 11 17 8f ?? 00 00 01 25 71 ?? 00 00 01 11 05 11 13 6f ?? 00 00 0a a5 ?? 00 00 01 61 d2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

