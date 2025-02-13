rule Backdoor_Linux_Tigrbot_A_2147684904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tigrbot.A"
        threat_id = "2147684904"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tigrbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 6f 6d 2f 61 6e 64 72 6f 69 64 6b 65 72 6e 65 6c 2f 66 6c 61 73 68 2f 68 65 6c 70 65 72 2f 54 69 67 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {26 4e 48 56 47 4b 5e 31 37 54 28 25 47 4e 4a 45 5e 4e 47 36 00}  //weight: 1, accuracy: High
        $x_1_3 = {2b 38 36 31 35 30 35 33 35 39 33 34 38 30 00 00 44 45 34 36 42 35 35 45 44 46 43 38 46 42 39 35 46 45 31 32 33 32 42 39 36 41 36 31 31 46 42 36 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

