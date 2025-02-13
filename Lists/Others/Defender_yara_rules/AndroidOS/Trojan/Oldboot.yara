rule Trojan_AndroidOS_Oldboot_A_2147685105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Oldboot.A"
        threat_id = "2147685105"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Oldboot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 7a 79 36 2e 63 6f 6d 2c 6c 61 6e 64 66 79 2e 63 6f 6d 2c 33 36 36 6a 6f 62 73 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_2 = {61 6e 64 72 6f 6c 64 39 39 39 2e 63 6f 6d 3a 38 30 39 30 2f 62 61 63 6b 75 72 6c 2e 64 6f 00}  //weight: 1, accuracy: High
        $x_1_3 = {61 6e 64 72 6f 69 64 2e 67 6f 6f 67 6c 65 6b 65 72 6e 65 6c 2f 2f 64 62 2f 2f 69 74 2e 69 00}  //weight: 1, accuracy: High
        $x_1_4 = {3a 38 30 39 30 2f 69 6e 73 74 61 6c 6c 61 70 70 2e 64 6f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Oldboot_A_2147685105_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Oldboot.A"
        threat_id = "2147685105"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Oldboot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3f 63 61 72 64 69 64 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = {26 61 70 70 69 64 3d 00 0b 26 63 68 61 6e 6e 65 6c 69 64 3d 00 05 26 6e 65 74 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {31 30 2e 30 2e 30 2e 31 37 32 00 0a 31 30 2e 30 2e 30 2e 32 30 30 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 65 72 76 69 63 65 2f 42 6f 6f 74 52 65 63 76 3b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

