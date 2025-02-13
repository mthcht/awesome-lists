rule Trojan_MSIL_Hive_NEAA_2147836649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hive.NEAA!MTB"
        threat_id = "2147836649"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hive"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 08 06 08 1e 5a 1e 6f ?? 00 00 0a 18 28 ?? 00 00 0a 9c 08 17 58 0c 08 07 8e 69 17 59 31 e1}  //weight: 10, accuracy: Low
        $x_5_2 = "1A0571712A2F303411151A162C0A02322A2F2B7F" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

