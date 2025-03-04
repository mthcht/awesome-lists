rule Trojan_MSIL_Xloader_OAW_2147826894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xloader.OAW!MTB"
        threat_id = "2147826894"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 02 8e 69 17 59 91 1f 70 61 0b 1f 0b 13 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

