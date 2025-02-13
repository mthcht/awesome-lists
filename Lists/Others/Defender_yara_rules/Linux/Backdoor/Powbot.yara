rule Backdoor_Linux_Powbot_A_2147689305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Powbot.A"
        threat_id = "2147689305"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Powbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 69 6c 6c 00 75 64 70 00 73 79 6e 00 74 63 70 61 6d 70 00 64 69 6c 64 6f 73 00 68 74 74 70 00 6d 69 6e 65 6c 6f 72 69 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {38 39 2e 32 33 38 2e 31 35 30 2e 31 35 34 00 56 79 70 6f 72 00 77 6f 70 62 6f 74 20 68 61 73 20 73 74 61 72 74 65 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

