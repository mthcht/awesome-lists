rule Trojan_MSIL_Grotseento_A_2147687524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Grotseento.A"
        threat_id = "2147687524"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Grotseento"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 61 79 6e 61 6b 6c 69 6e 6b 69 00 70 72 65 6c 69 6b 61 79 6e 61 6b 6b 6f 64 75 00 6d 61 6e 69 64 65 67 65 72 00 63 72 78 6b 6f 64 75 00 61 6e 61 68 74 61 72}  //weight: 1, accuracy: High
        $x_1_2 = {6b 6f 79 76 65 72 67 69 74 73 69 6e 00 63 72 6f 6d 64 6f 63 75 6d 65 6e 74 00 63 72 6f 6d 64 65 66 65 61 75 6c 74 00 63 72 78 79 6f 6c}  //weight: 1, accuracy: High
        $x_1_3 = {66 65 64 61 68 61 62 65 72 2e 63 6f 6d 2f 22 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

