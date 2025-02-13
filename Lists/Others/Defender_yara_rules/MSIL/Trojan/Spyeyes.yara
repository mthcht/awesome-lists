rule Trojan_MSIL_Spyeyes_RPY_2147892355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spyeyes.RPY!MTB"
        threat_id = "2147892355"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spyeyes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 02 07 6f 11 00 00 0a 7e 01 00 00 04 07 7e 01 00 00 04 8e 69 5d 91 61 28 09 00 00 0a 6f 14 00 00 0a 26 07 17 58 0b 07 02 6f 12 00 00 0a 32 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

