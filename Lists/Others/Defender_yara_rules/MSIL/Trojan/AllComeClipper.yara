rule Trojan_MSIL_AllComeClipper_A_2147836287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AllComeClipper.A!MTB"
        threat_id = "2147836287"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AllComeClipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KJKJFS8Y8M,ZF" wide //weight: 1
        $x_1_2 = "IKJKJFS8Y8M,ZFF" wide //weight: 1
        $x_1_3 = "DFSKJKJFS8Y8M,ZFAWWR" wide //weight: 1
        $x_1_4 = "ToInteger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AllComeClipper_B_2147837082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AllComeClipper.B!MTB"
        threat_id = "2147837082"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AllComeClipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 03 8e 69 14 14 17 28 ?? 00 00 06 d6 13 05 11 05 04 5f 13 06 03 11 04 03 8e 69 14 14 17 28 ?? 00 00 06 91 13 07 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

