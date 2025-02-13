rule Backdoor_Linux_WolfsBane_A_2147932203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/WolfsBane.A!MTB"
        threat_id = "2147932203"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "WolfsBane"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 2f 62 69 6e 2f 00 2f 75 73 72 2f 62 69 6e 2f 2e 58 6c 31 2f 66 31 00 2f 75 73 72 2f 62 69 6e 2f 2e 58 6c 31 2f 66 32 00}  //weight: 1, accuracy: High
        $x_1_2 = {30 32 64 00 25 49 36 34 64 00 36 34 00 2f 65 74 63 2f 6c 64 2e 73 6f 2e 70 72 65 6c 6f 61 64 00 6b 69 6c 6c 20 2d 39 20 25 64 20 32 3e 2f 64 65 76 2f 6e 75 6c 6c 00 6b 69 6c 6c 65 72 00 62 61 73 69 63 5f 73 74 72 69 6e 67 3a 3a 5f 53 5f 63 6f 6e 73 74 72 75 63 74 20 4e 55 4c 4c 20 6e 6f 74 20 76 61 6c 69 64 00 00 00 00 00 00 00 6b 65 65 70 5f 61 6c 69 76 65 5f 63 6f 6d 6d 61 6e 64 3a 3a 77 72 69 74 65 5f 64 61 74 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

