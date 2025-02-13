rule Trojan_MSIL_Trecstart_A_2147697147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Trecstart.A"
        threat_id = "2147697147"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Trecstart"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 61 74 65 66 75 74 2e 65 78 65 00 73 61 74 65 66 75 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {04 4c 6f 61 64 ?? ?? ?? ?? ?? 34 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 64 6f 77 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 65 72 74 50 72 6f 70 53 76 63 ?? ?? ?? ?? ?? ?? 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 65 72 74 50 72 6f 70 53 76 63}  //weight: 1, accuracy: Low
        $x_1_4 = {69 75 62 65 61 6d 2e 65 78 65 00 69 75 62 65 61 6d 00 6d 73 63 6f 72 6c 69 62}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

