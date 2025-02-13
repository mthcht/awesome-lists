rule Backdoor_Linux_Setag_A_2147690343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Setag.gen!A"
        threat_id = "2147690343"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Setag"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 32 43 55 70 64 61 74 65 47 61 74 65 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {31 31 43 55 70 64 61 74 65 42 69 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 74 6d 70 2f 67 61 74 65 73 2e 6c 6f 63 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 74 6d 70 2f 62 69 6c 6c 2e 6c 6f 63 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

