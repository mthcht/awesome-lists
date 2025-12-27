rule Trojan_PHP_Reverseshell_SR10_2147950260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PHP/Reverseshell.SR10"
        threat_id = "2147950260"
        type = "Trojan"
        platform = "PHP: Hypertext Preprocessor scripts"
        family = "Reverseshell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {3d 00 66 00 73 00 6f 00 63 00 6b 00 6f 00 70 00 65 00 6e 00 28 00 [0-64] 2c 00 [0-64] 29 00 3b 00}  //weight: 10, accuracy: Low
        $x_1_2 = "/bin/sh -i <&3 >&3 2>&3" wide //weight: 1
        $x_1_3 = "/bin/bash -i <&3 >&3 2>&3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_PHP_Reverseshell_SR11_2147950261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PHP/Reverseshell.SR11"
        threat_id = "2147950261"
        type = "Trojan"
        platform = "PHP: Hypertext Preprocessor scripts"
        family = "Reverseshell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {3d 00 66 00 73 00 6f 00 63 00 6b 00 6f 00 70 00 65 00 6e 00 28 00 [0-64] 2c 00 [0-64] 29 00 3b 00}  //weight: 10, accuracy: Low
        $x_1_2 = {65 00 78 00 65 00 63 00 28 00 22 00 2f 00 62 00 69 00 6e 00 2f 00 73 00 68 00 [0-96] 22 00 29 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_3 = {65 00 78 00 65 00 63 00 28 00 22 00 2f 00 62 00 69 00 6e 00 2f 00 62 00 61 00 73 00 68 00 [0-96] 22 00 29 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_4 = {73 00 79 00 73 00 74 00 65 00 6d 00 28 00 22 00 2f 00 62 00 69 00 6e 00 2f 00 73 00 68 00 [0-96] 22 00 29 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_5 = {73 00 79 00 73 00 74 00 65 00 6d 00 28 00 22 00 2f 00 62 00 69 00 6e 00 2f 00 62 00 61 00 73 00 68 00 [0-96] 22 00 29 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_6 = {70 00 6f 00 70 00 65 00 6e 00 28 00 22 00 2f 00 62 00 69 00 6e 00 2f 00 73 00 68 00 [0-96] 22 00 29 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_7 = {70 00 6f 00 70 00 65 00 6e 00 28 00 22 00 2f 00 62 00 69 00 6e 00 2f 00 62 00 61 00 73 00 68 00 [0-96] 22 00 29 00 3b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

