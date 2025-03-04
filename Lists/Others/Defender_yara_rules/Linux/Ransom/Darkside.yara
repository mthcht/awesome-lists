rule Ransom_Linux_DarkSide_A_2147776592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/DarkSide.A!MTB"
        threat_id = "2147776592"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "DarkSide"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Welcome to DarkSide" ascii //weight: 1
        $x_1_2 = "Your computers and servers are encrypted, backups are deleted" ascii //weight: 1
        $x_1_3 = "darkside_readme.txt" ascii //weight: 1
        $x_1_4 = {50 61 72 74 69 61 6c 20 46 69 6c 65 20 45 6e 63 72 79 70 74 69 6f 6e 20 54 6f 6f 6c [0-32] 50 61 72 74 69 61 6c 46 69 6c 65 43 72 79 70 74 65 72 20 5b 2d 68 5d 20 5b 2d 66 3a 66 69 6c 65 5d 20 5b 2d 73 3a 73 69 7a 65 5d 20 5b 2d 6b 3a 6b 65 79 5d [0-37] 50 61 72 74 69 61 6c 46 69 6c 65 43 72 79 70 74 65 72 20 20 2d 66 20 69 6e 70 75 74 2e 66 69 6c 65}  //weight: 1, accuracy: Low
        $x_1_5 = "/tmp/software.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

