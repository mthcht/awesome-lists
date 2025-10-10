rule Trojan_MSIL_Johnnie_AJO_2147939558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Johnnie.AJO!MTB"
        threat_id = "2147939558"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Johnnie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 da 0c 0b 2b 30 03 07 91 20 ff 00 00 00 fe 01 16 fe 01 13 05 11 05 2c 12 03 0d 09 07 13 04 11 04 09 11 04 91 17 d6 b4 9c 2b 05 00 03 07 16 9c 00 00 07 17 d6 0b 07 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Johnnie_CC_2147954746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Johnnie.CC!MTB"
        threat_id = "2147954746"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Johnnie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1c 9a 0b 07 6f ?? ?? ?? ?? 0c 08 6c 23 ?? ?? ?? ?? ?? ?? ?? ?? 5b 23 ?? ?? ?? ?? ?? ?? ?? ?? 59 28 ?? 00 00 0a b7 17 d6 8d ?? ?? ?? ?? 0d 08 17 da 13 04 16 13 05 2b 2b}  //weight: 5, accuracy: Low
        $x_5_2 = {09 11 05 6c 23 ?? ?? ?? ?? ?? ?? ?? ?? 5b 28 ?? 00 00 0a b7 07 11 05 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 11 05 18 d6 13 05 11 05 11 04 31 cf}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

