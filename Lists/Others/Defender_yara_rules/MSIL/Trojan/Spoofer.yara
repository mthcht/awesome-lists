rule Trojan_MSIL_Spoofer_MX_2147962959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spoofer.MX!MTB"
        threat_id = "2147962959"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spoofer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 05 06 6f 7b 00 00 0a 0b de 0c 11 05 2c 07 11 05 6f 0f 00 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = "Temp Spoof" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

