rule Trojan_MSIL_TurtleLoader_NT_2147899463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TurtleLoader.NT!MTB"
        threat_id = "2147899463"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TurtleLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 10 00 00 0a 0c 06 08 07 6f ?? 00 00 06 0d 7e ?? 00 00 0a 09 8e 69 7e ?? 00 00 04 7e ?? 00 00 04 28 ?? 00 00 06 13 04 09 16 11 04 09 8e 69 28 ?? 00 00 0a 1f 18 16 28 ?? 00 00 06 28 ?? 00 00 06 13 05 11 04 11 05 7e ?? 00 00 0a 28 ?? 00 00 06}  //weight: 5, accuracy: Low
        $x_1_2 = "apool.exe" ascii //weight: 1
        $x_1_3 = "zhudongfangyu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_TurtleLoader_CNQ_2147904366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TurtleLoader.CNQ"
        threat_id = "2147904366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TurtleLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Canon.QuickMenu.Utility" ascii //weight: 1
        $x_1_2 = "CNQMUTIL" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_TurtleLoader_AW_2147956725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TurtleLoader.AW!MTB"
        threat_id = "2147956725"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TurtleLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 05 00 00 0a 13 04 20 ff 0f 1f 00 16 11 04 6f 06 00 00 0a 28 08 00 00 06 13 05 11 05 7e 07 00 00 0a 09 8e 69 20 00 30 00 00 1f 40 28 04 00 00 06 13 06 16 13 07 38 18 00 00 00 09 11 07 07 11 07 91 08 11 07 08 8e 69 5d 91 61 d2 9c 11 07 17 58 13 07}  //weight: 2, accuracy: High
        $x_2_2 = {11 05 11 06 09 09 8e 69 12 08 28 05 00 00 06 26 11 05 7e 07 00 00 0a 16 11 06 7e 07 00 00 0a 16 12 09 28 06 00 00 06 26 11 05 28 07 00 00 06 26 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

