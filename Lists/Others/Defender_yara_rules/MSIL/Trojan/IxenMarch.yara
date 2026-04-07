rule Trojan_MSIL_IxenMarch_A_2147966411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/IxenMarch.A!dha"
        threat_id = "2147966411"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "IxenMarch"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 47 65 74 57 6f 72 6b 61 62 6c 65 4c 6f 67 69 63 61 6c 44 72 69 76 65 73 50 61 74 68 65 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 46 69 6c 65 4d 61 6e 61 67 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 50 61 72 73 65 50 61 74 68 44 69 72 65 63 74 6f 72 69 65 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 50 72 6f 63 65 73 73 65 73 46 69 6c 65 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

