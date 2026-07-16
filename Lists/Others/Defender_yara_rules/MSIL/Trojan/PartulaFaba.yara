rule Trojan_MSIL_PartulaFaba_A_2147973491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PartulaFaba.A!dha"
        threat_id = "2147973491"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PartulaFaba"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 20 00 00 00 40 16 7e 21 00 00 0a 18 20 80 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {0b 02 20 00 00 00 80 17 7e 21 00 00 0a 19 20 80 00 00 00 7e 21 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

