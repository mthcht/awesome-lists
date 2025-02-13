rule Trojan_MSIL_Lagos_MBEN_2147895385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lagos.MBEN!MTB"
        threat_id = "2147895385"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lagos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 0a 06 02 7d 01 00 00 04 00 16 06 7b}  //weight: 1, accuracy: High
        $x_1_2 = "SKSMKWCNJwBqJ" ascii //weight: 1
        $x_1_3 = "StringToByteArray" ascii //weight: 1
        $x_1_4 = "OUjgoT" ascii //weight: 1
        $x_1_5 = "Veil.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

