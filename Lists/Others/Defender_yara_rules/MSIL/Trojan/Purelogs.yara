rule Trojan_MSIL_Purelogs_HHE_2147935339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Purelogs.HHE!MTB"
        threat_id = "2147935339"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Purelogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 06 04 6f ?? 00 00 0a 73 ?? 00 00 0a 0b 07 20 ?? 1c 00 00 28 ?? 02 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 07 20 ?? 1b 00 00 28 ?? 02 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 07 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0c de 1b}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

