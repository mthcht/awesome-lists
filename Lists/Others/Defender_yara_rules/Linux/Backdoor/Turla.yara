rule Backdoor_Linux_Turla_C_2147836888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Turla.C"
        threat_id = "2147836888"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Turla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "___123!@#" ascii //weight: 5
        $x_5_2 = "___456$$$" ascii //weight: 5
        $x_5_3 = {8b 01 83 c1 04 8d 90 ff fe fe fe f7 d0 21 c2 81 e2 80 80 80 80 74 e9}  //weight: 5, accuracy: High
        $x_10_4 = "__we_are_happy__" ascii //weight: 10
        $x_10_5 = {c7 85 e8 af ff ff 5f 5f 77 65 c7 85 ec af ff ff 5f 61 72 65 c7 85 f0 af ff ff 5f 68 61 70 c7 85 f4 af ff ff 70 79 5f 5f}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_5_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Turla_D_2147836889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Turla.D"
        threat_id = "2147836889"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Turla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c6 05 74 70 29 00 5f c6 05 6e 70 29 00 5f c6 05 68 70 29 00 77}  //weight: 10, accuracy: High
        $x_10_2 = {c6 05 5f 70 29 00 65 c6 05 59 70 29 00 5f c6 05 53 70 29 00 61 c6 05 4d 70 29 00 72 c6 05 47 70 29 00 65 c6 05 41 70 29 00 5f c6 05 3b 70 29 00 68 c6 05 35 70 29 00 61 c6 05 2f 70 29 00 70 c6 05 29 70 29 00 70 c6 05 23 70 29 00 79 c6 05 1d 70 29 00 5f c6 05 17 70 29 00 5f}  //weight: 10, accuracy: High
        $x_10_3 = {8b 02 48 83 c2 04 8d 88 ff fe fe fe f7 d0 21 c1 81 e1 80 80 80 80 74 e8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Turla_M_2147843701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Turla.M"
        threat_id = "2147843701"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Turla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {81 e2 e0 01 00 00 c1 e2 11 81 e3 3f fc 3f fc 09 d3 89 ca 81 e1 00 80 00 00 81 e2 80 03 00 00 c1 f9 06 d1 fa}  //weight: 5, accuracy: High
        $x_5_2 = {66 c1 c9 08 89 ca 81 e1 00 e0 00 00 83 e2 07 c1 f9 0a}  //weight: 5, accuracy: High
        $x_5_3 = {25 c0 01 00 00 81 e2 00 02 00 00 01 c0 81 e6 7f 7c 00 00 c1 e2 06}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Turla_G_2147843702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Turla.G"
        threat_id = "2147843702"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Turla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {66 c1 c8 08 25 e0 01 00 00 c1 e0 11 41 81 e1 3f fc 3f fc 41 09 c1 89 d0 81 e2 00 80 00 00 25 80 03 00 00 c1 fa 06 d1 f8}  //weight: 5, accuracy: High
        $x_5_2 = {66 c1 c8 08 89 c2 83 e0 07 81 e2 00 e0 00 00 c1 fa 0a}  //weight: 5, accuracy: High
        $x_5_3 = {25 c0 01 00 00 01 c0 81 e1 7f 7c 00 00 09 c1 89 f0 81 e6 00 00 c0 03 25 00 02 00 00 c1 ee 16 c1 e0 06}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Turla_O_2147849464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Turla.O"
        threat_id = "2147849464"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Turla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 41 05 32 06 48 ff c6 88 81 e0 80 69 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 ff c1 48 83 f9 49 75 e9}  //weight: 1, accuracy: High
        $x_1_3 = {c7 05 9b 7d 29 00 1d 00 00 00 c7 05 2d 7b 29 00 65 74 68 30 c6 05 2a 7b 29 00 00 e8}  //weight: 1, accuracy: High
        $x_1_4 = {bf ff ff ff ff e8 96 9d 0a 00 90 90 90 90 90 90 90 90 90 90 89 f0}  //weight: 1, accuracy: High
        $x_1_5 = {88 d3 80 c3 05 32 9a c1 d6 0c 08 88 9a 60 a1 0f 08 42 83 fa 08 76 e9}  //weight: 1, accuracy: High
        $x_1_6 = {8b 8d 50 df ff ff b8 09 00 00 00 89 44 24 04 89 0c 24 e8 dd e5 02 00}  //weight: 1, accuracy: High
        $x_1_7 = {8d 5a 05 32 9a 60 26 0c 08 88 9a 20 f4 0e 08 42 83 fa 48 76 eb}  //weight: 1, accuracy: High
        $x_1_8 = {8d 4a 05 32 8a 25 26 0c 08 88 8a 20 f4 0e 08 42 83 fa 08 76 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

