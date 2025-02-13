rule Trojan_MSIL_Cinoshi_NEAA_2147844547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cinoshi.NEAA!MTB"
        threat_id = "2147844547"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cinoshi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "5f2c57b2-ad10-46d8-9002-4a0e9a7dfe14" ascii //weight: 2
        $x_2_2 = "Johny.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

