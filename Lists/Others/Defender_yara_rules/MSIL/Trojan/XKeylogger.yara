rule Trojan_MSIL_XKeylogger_A_2147848992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XKeylogger.A!MTB"
        threat_id = "2147848992"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 00 01 14 14 14 28}  //weight: 2, accuracy: High
        $x_2_2 = {00 00 01 13 4d 11 4d 16 14 a2}  //weight: 2, accuracy: High
        $x_2_3 = {11 4d 17 14 a2}  //weight: 2, accuracy: High
        $x_2_4 = {11 4d 14 14 14 28}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

