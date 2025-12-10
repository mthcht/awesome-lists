rule Trojan_PowerShell_PsAttack_A_2147725500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/PsAttack.A"
        threat_id = "2147725500"
        type = "Trojan"
        platform = "PowerShell: "
        family = "PsAttack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 00 6d 00 73 00 69 00 75 00 74 00 69 00 6c 00 73 00 [0-16] 67 00 65 00 74 00 66 00 69 00 65 00 6c 00 64 00 28 00 [0-16] 61 00 6d 00 73 00 69 00 69 00 6e 00 69 00 74 00 66 00 61 00 69 00 6c 00 65 00 64 00}  //weight: 1, accuracy: Low
        $x_1_2 = {61 00 6d 00 73 00 69 00 63 00 6f 00 6e 00 74 00 65 00 78 00 74 00 [0-16] 5b 00 72 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 62 00 69 00 6e 00 64 00 69 00 6e 00 67 00 66 00 6c 00 61 00 67 00 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5b 00 72 00 65 00 66 00 5d 00 2e 00 61 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 2e 00 67 00 65 00 74 00 74 00 79 00 70 00 65 00 28 00 [0-2] 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 6d 00 61 00 6e 00 61 00 67 00 65 00 6d 00 65 00 6e 00 74 00 2e 00 61 00 75 00 74 00 6f 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 61 00 6d 00 73 00 69 00 75 00 74 00 69 00 6c 00 73 00}  //weight: 1, accuracy: Low
        $x_1_4 = {61 00 6d 00 73 00 69 00 75 00 74 00 69 00 6c 00 73 00 [0-16] 2e 00 67 00 65 00 74 00 66 00 69 00 65 00 6c 00 64 00 28 00 [0-16] 61 00 6d 00 73 00 69 00 63 00 6f 00 6e 00 74 00 65 00 78 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_PowerShell_PsAttack_B_2147830457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/PsAttack.B"
        threat_id = "2147830457"
        type = "Trojan"
        platform = "PowerShell: "
        family = "PsAttack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "yqbtahmaaqbjag4aaqb0aeyayqbpagwazqbkaa" wide //weight: 10
        $x_10_2 = "nonpublic,static" wide //weight: 10
        $x_10_3 = "setvalue($null,$true)" wide //weight: 10
        $x_10_4 = "[ref].assembly.gettype" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_PowerShell_PsAttack_R_2147959148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/PsAttack.R"
        threat_id = "2147959148"
        type = "Trojan"
        platform = "PowerShell: "
        family = "PsAttack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "amsiutils" wide //weight: 10
        $x_10_2 = "amsiinitfailed" wide //weight: 10
        $x_1_3 = "getfield" wide //weight: 1
        $x_1_4 = "nonpublic,static" wide //weight: 1
        $x_1_5 = "setvalue" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

