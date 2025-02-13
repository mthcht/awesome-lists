rule Trojan_MSIL_QQPass_NIT_2147926894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QQPass.NIT!MTB"
        threat_id = "2147926894"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QQPass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 18 02 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 13 1d 2b 45 11 1d 6f ?? 00 00 0a 74 1a 00 00 01 13 1e 00 72 64 05 00 70 13 1f 11 1e 6f ?? 00 00 0a 1b 6f ?? 00 00 0a 6f ?? 00 00 0a 13 20 02 73 2c 00 00 0a 28 ?? 00 00 06 00 02 28 ?? 00 00 06 11 20 6f ?? 00 00 0a 00 00 11 1d 6f ?? 00 00 0a 2d b2 de 16}  //weight: 2, accuracy: Low
        $x_1_2 = "TUKSystemForSell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QQPass_NIT_2147926894_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QQPass.NIT!MTB"
        threat_id = "2147926894"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QQPass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 e1 02 00 70 13 18 02 28 ?? 00 00 06 11 13 11 15 20 00 04 00 00 12 17 28 ?? 00 00 06 26 72 19 03 00 70 13 19 28 ?? 00 00 0a 11 15 6f ?? 00 00 0a 6f ?? 00 00 0a 13 1a 72 49 03 00 70 13 1b 00 11 1a 02 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 13 1d 2b 38 11 1d 6f ?? 00 00 0a 74 16 00 00 01 13 1e 00 72 87 03 00 70 13 1f 02 11 1e 6f ?? 00 00 0a 1f 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 06 00 72 af 03 00 70 13 20 00 11 1d 6f ?? 00 00 0a 2d bf de 16}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

