rule Trojan_MSIL_Oryecux_A_2147707665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Oryecux.A"
        threat_id = "2147707665"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Oryecux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {91 61 9c 06 17 d6 0a 06 08 31 d1}  //weight: 1, accuracy: High
        $x_1_2 = "Important.exe" wide //weight: 1
        $x_1_3 = "MemoryEx" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

