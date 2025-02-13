rule Trojan_MSIL_Razzy_RPZ_2147846586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razzy.RPZ!MTB"
        threat_id = "2147846586"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razzy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 05 00 00 04 06 7e 05 00 00 04 06 91 06 61 20 aa 00 00 00 61 d2 9c 06 17 58 0a 06 7e 05 00 00 04 8e 69 fe 04 2d d9}  //weight: 1, accuracy: High
        $x_1_2 = "DataEstateAssessment.script.ps1" ascii //weight: 1
        $x_1_3 = "E9D4DF25-223E-444F-BC72-547D07F6C870" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "ConsoleShell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

