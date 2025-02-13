rule Trojan_MSIL_GraceWire_DA_2147781174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GraceWire.DA!MTB"
        threat_id = "2147781174"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {04 17 9a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 06 80 ?? ?? ?? 04 20 e4 04 00 00 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 17 9a 6f ?? ?? ?? 0a 26 38 2a 00 00 00 20 04 00 00 00 fe 0e 00 00 fe 0c 00 00}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "Activator" ascii //weight: 1
        $x_1_5 = "Convert" ascii //weight: 1
        $x_1_6 = "ToString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

