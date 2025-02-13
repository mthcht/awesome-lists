rule Trojan_MSIL_Norewor_A_2147705772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Norewor.A"
        threat_id = "2147705772"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Norewor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 65 79 6c 6f 67 00 74 00 75 70 6c 6f 61 64 5f 73 65 72 76 65 72 00 6b 69 6c 6c 5f 6d 65}  //weight: 1, accuracy: High
        $x_1_2 = "- Fake image shown..." wide //weight: 1
        $x_1_3 = "|WDOR+NORRE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

