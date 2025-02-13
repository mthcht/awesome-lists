rule Trojan_MSIL_Zenpak_PSUN_2147852737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zenpak.PSUN!MTB"
        threat_id = "2147852737"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 3b 00 00 70 11 0a 28 ?? 00 00 0a 72 73 00 00 70 72 79 00 00 70 6f ?? 00 00 0a 1f 5c 1f 2f 6f ?? 00 00 0a 13 0b 11 0b 28 ?? 00 00 0a 13 0b 06 11 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

