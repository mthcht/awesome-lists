rule Trojan_MSIL_Dogstop_A_2147639538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dogstop.A"
        threat_id = "2147639538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dogstop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c2 a9 20 48 61 63 6b 69 6e 67 20 26 20 43 6f}  //weight: 1, accuracy: High
        $x_1_2 = "K9Remover.Resources" wide //weight: 1
        $x_1_3 = "Now attempting to remove K9 Driver" wide //weight: 1
        $x_1_4 = {4d 79 41 70 70 6c 69 63 61 74 69 6f 6e 00 4b 39 52 65 6d 6f 76 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

