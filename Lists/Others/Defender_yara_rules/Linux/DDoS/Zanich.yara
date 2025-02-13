rule DDoS_Linux_Zanich_A_2147691151_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Zanich.A"
        threat_id = "2147691151"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Zanich"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 6e 74 20 53 65 72 76 65 72 2e 2e 2e 00 43 68 69 6e 61 5a 00 63 6f 6e 6e 65 63 74 20 74 6f 20 73 65 72 76 65 72 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 65 64 20 2d 69 20 2d 65 20 27 32 20 69 25 73 2f 25 73 27 20 2f 65 74 63 2f 72 63 2e 6c 6f 63 61 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule DDoS_Linux_Zanich_B_2147691152_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Zanich.B"
        threat_id = "2147691152"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Zanich"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 4b 33 32 20 53 65 63 75 72 74 44 6f 6f 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 4b 36 34 20 53 65 63 75 72 74 44 6f 6f 72 00}  //weight: 1, accuracy: High
        $x_4_3 = "Ddos ATTACE!" ascii //weight: 4
        $x_4_4 = "COMMAND_DDOS_STOP" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule DDoS_Linux_Zanich_C_2147691153_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Zanich.C"
        threat_id = "2147691153"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Zanich"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 74 6d 70 2f 2e 44 44 6f 73 43 6c 69 65 6e 74 55 70 64 61 74 65 72 2e 73 6f 63 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 76 20 44 44 6f 73 43 6c 69 65 6e 74 2e 62 61 63 6b 20 44 44 6f 73 43 6c 69 65 6e 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

