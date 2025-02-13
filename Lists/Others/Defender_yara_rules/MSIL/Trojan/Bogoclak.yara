rule Trojan_MSIL_Bogoclak_A_2147641177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bogoclak.A"
        threat_id = "2147641177"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bogoclak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "User send you message :" wide //weight: 1
        $x_1_2 = {53 63 72 65 6e 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = "buffCritery" ascii //weight: 1
        $x_1_4 = "CherezShto" ascii //weight: 1
        $x_1_5 = "Backdoor>b__" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

