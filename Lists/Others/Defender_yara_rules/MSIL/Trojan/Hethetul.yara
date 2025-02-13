rule Trojan_MSIL_Hethetul_A_2147773732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hethetul.A!MSR"
        threat_id = "2147773732"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hethetul"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 0c 02 08 8f 7d 00 00 01 25 71 7d 00 00 01 06 07 1f 0a 5d 91 61 d2 81 7d 00 00 01 07 17 58 0b 07 02 8e 69 32 da 02 2a}  //weight: 1, accuracy: High
        $x_1_2 = "Users\\Hac TooL\\Desktop\\Het\\Het" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

