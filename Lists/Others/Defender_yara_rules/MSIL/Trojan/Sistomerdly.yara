rule Trojan_MSIL_Sistomerdly_A_2147640586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Sistomerdly.A"
        threat_id = "2147640586"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sistomerdly"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 6e 69 74 44 65 73 74 72 75 63 74 69 6f 6e 00 69 6e 69 74 42 6f 6d 62}  //weight: 1, accuracy: High
        $x_1_2 = {64 65 73 74 72 6f 79 46 69 6c 65 53 79 73 74 65 6d 00 64 65 73 74 72 6f 79 50 72 6f 66 69 6c 65 73 00 64 65 73 74 72 6f 79 50 72 6f 67 72 61 6d 46 69 6c 65 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

