rule Trojan_MSIL_QuasarStealer_EA_2147937249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarStealer.EA!MTB"
        threat_id = "2147937249"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 07 02 07 91 03 07 03 6f 20 00 00 0a 5d 6f 21 00 00 0a 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

