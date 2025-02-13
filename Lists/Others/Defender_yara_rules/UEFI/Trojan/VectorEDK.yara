rule Trojan_UEFI_VectorEDK_RKL_2147765712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:UEFI/VectorEDK.RKL"
        threat_id = "2147765712"
        type = "Trojan"
        platform = "UEFI: "
        family = "VectorEDK"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ec 9a ea ea c1 c9 e2 46 9d 52 43 2a d2 5a 9b 0b}  //weight: 2, accuracy: High
        $x_1_2 = {b3 8f e8 7c d7 4b 79 46 87 a8 a8 d8 de e5 0d 2b}  //weight: 1, accuracy: High
        $x_1_3 = {45 33 c9 4c 8d 05 ?? ?? ?? ?? ba 10 00 00 00 b9 00 02 00 00 48 8b 05 ?? ?? ?? ?? ff ?? 70 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_UEFI_VectorEDK_D_2147765713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:UEFI/VectorEDK.D"
        threat_id = "2147765713"
        type = "Trojan"
        platform = "UEFI: "
        family = "VectorEDK"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 b9 03 00 00 00 00 00 00 80 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ff ?? 08}  //weight: 1, accuracy: Low
        $x_1_2 = {41 b9 03 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ff ?? 08}  //weight: 1, accuracy: Low
        $x_1_3 = {61 df e4 8b ca 93 d2 11 aa 0d 00 e0 98 30 22 88}  //weight: 1, accuracy: High
        $x_1_4 = {a1 31 1b 5b 62 95 d2 11 8e 3f 00 a0 c9 69 72 3b}  //weight: 1, accuracy: High
        $x_1_5 = {22 5b 4e 96 59 64 d2 11 8e 39 00 a0 c9 69 72 3b}  //weight: 1, accuracy: High
        $x_1_6 = {66 00 54 00 41 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = ".sraw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

