rule Trojan_MSIL_Ainslot_A_2147657619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ainslot.A"
        threat_id = "2147657619"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ainslot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 08 8e 69 32 b7 06 28 4b 00 00 06 6f 29 00 00 0a 2d 1a 28 2a 00 00 0a 28 49 00 00 06 28 4a 00 00 06 28 2b 00 00 0a 28 2c 00 00 0a 26}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ainslot_2147740084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ainslot!MTB"
        threat_id = "2147740084"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ainslot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ROhCHywbIrWJbshraSWRjaUbH" ascii //weight: 1
        $x_1_2 = "sxLlgcTVQULbUKqJYhxGIFeil.Resources" ascii //weight: 1
        $x_1_3 = "eQkpLSSYYhDfbboUqcIpaCwPZ" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_MSIL_Ainslot_ADT_2147781327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ainslot.ADT!MTB"
        threat_id = "2147781327"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ainslot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 11 05 02 11 05 91 06 61 09 11 04 91 61 b4 9c 11 04 03 6f ?? ?? ?? 0a 17 da 33 05 16 13 04 2b 06 11 04 17 d6 13 04 11 05 17 d6 13 05 11 05 11 06}  //weight: 10, accuracy: Low
        $x_5_2 = "get_ExecutablePath" ascii //weight: 5
        $x_5_3 = "FromBase64String" ascii //weight: 5
        $x_4_4 = "fGpuzj5dpQGp5igZ0c6JHy8knSdrhq5LWIcwCJASTjs" ascii //weight: 4
        $x_4_5 = "JgtG/lRwSzgVYnWYV7K5by5WLSz2C07dKFIE/Pmc4HI" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

