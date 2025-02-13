rule Backdoor_Linux_Xnote_A_2147692470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Xnote.A"
        threat_id = "2147692470"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Xnote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 65 74 63 2f 2e 58 73 65 72 76 65 72 5f 6e 6f 74 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {61 6c 72 65 61 64 79 20 73 74 61 72 74 20 61 20 64 64 6f 73 20 73 79 6e 20 74 61 73 6b 20 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 74 6d 70 2f 2e 77 71 34 73 4d 4c 41 72 58 77 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

