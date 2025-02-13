rule Trojan_MSIL_Mozifox_A_2147646523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mozifox.A"
        threat_id = "2147646523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mozifox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 46 69 72 65 66 6f 78 4b 75 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 67 65 74 5f 66 69 72 65 66 6f 78 00}  //weight: 1, accuracy: High
        $x_1_3 = {63 6f 6d 6d 61 6e 64 65 72 2e 66 69 72 65 66 6f 78 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 ?? ?? 4c 00 69 00 76 00 65 00 20 00 4d 00 65 00 73 00 73 00 65 00 6e 00 67 00 65 00 72 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_5 = {73 00 65 00 72 00 76 00 65 00 72 00 3d 00 ?? ?? 3b 00 20 00 75 00 69 00 64 00 3d 00 ?? ?? 3b 00 20 00 70 00 77 00 64 00 3d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

