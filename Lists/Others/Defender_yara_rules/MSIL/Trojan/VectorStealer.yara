rule Trojan_MSIL_VectorStealer_AAGZ_2147851539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VectorStealer.AAGZ!MTB"
        threat_id = "2147851539"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VectorStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {04 06 18 28 ?? 00 00 06 7e ?? 00 00 04 06 19 28 ?? 00 00 06 7e ?? 00 00 04 06 28 ?? 00 00 06 0d 7e ?? 00 00 04 09 05 16 05 8e 69 28 ?? 00 00 06 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VectorStealer_AAHB_2147851557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VectorStealer.AAHB!MTB"
        threat_id = "2147851557"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VectorStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {04 06 18 28 ?? 00 00 06 7e ?? 00 00 04 06 19 28 ?? 00 00 06 7e ?? 00 00 04 06 28 ?? 00 00 06 0d 7e ?? 00 00 04 09 04 16 04 8e 69 28 ?? 00 00 06 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VectorStealer_AAMX_2147888936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VectorStealer.AAMX!MTB"
        threat_id = "2147888936"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VectorStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 06 18 28 ?? 01 00 06 7e ?? 00 00 04 06 19 28 ?? 01 00 06 7e ?? 00 00 04 06 28 ?? 01 00 06 0d 7e ?? 00 00 04 09 05 16 05 8e 69 28 ?? 01 00 06 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

