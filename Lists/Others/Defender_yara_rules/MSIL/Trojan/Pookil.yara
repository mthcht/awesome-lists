rule Trojan_MSIL_Pookil_A_2147706840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Pookil.A"
        threat_id = "2147706840"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pookil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 00 70 00 61 00 74 00 65 00 44 00 4e 00 53 00 ?? ?? 57 00 69 00 72 00 65 00 73 00 68 00 61 00 72 00 6b 00 ?? ?? 6d 00 73 00 63 00 6f 00 6e 00 66 00 69 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = {54 00 61 00 73 00 6b 00 6d 00 67 00 72 00 ?? ?? 43 00 43 00 6c 00 65 00 61 00 6e 00 65 00 72 00 36 00 34 00 ?? ?? 43 00 43 00 6c 00 65 00 61 00 6e 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_3 = {70 00 72 00 6f 00 63 00 65 00 78 00 70 00 ?? ?? 70 00 72 00 6f 00 63 00 65 00 78 00 70 00 36 00 34 00 ?? ?? 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 48 00 61 00 63 00 6b 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_5_4 = {48 00 4b 00 45 00 59 00 5f 00 43 00 55 00 52 00 52 00 45 00 4e 00 54 00 5f 00 55 00 53 00 45 00 52 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 ?? ?? 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 75 00 70 00 64 00 61 00 74 00 65 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

