rule Trojan_MSIL_GravityRAT_SLCA_2147952157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GravityRAT.SLCA!MTB"
        threat_id = "2147952157"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GravityRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 9b 04 00 06 0a 06 03 6f 2e 00 00 0a 73 2f 00 00 0a 28 30 00 00 0a 72 e5 00 00 70 28 31 00 00 0a 7d 4a 02 00 04 28 32 00 00 0a 6f 33 00 00 0a 06 fe 06 9c 04 00 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

