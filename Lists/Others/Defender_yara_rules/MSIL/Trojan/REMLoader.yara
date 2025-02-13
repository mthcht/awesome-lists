rule Trojan_MSIL_REMLoader_RPV_2147834354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/REMLoader.RPV!MTB"
        threat_id = "2147834354"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "REMLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61}  //weight: 1, accuracy: High
        $x_1_2 = {5d d2 9c 00 07 15 58 0b 07 16 fe 04 16 fe 01 0c 08 2d b8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

