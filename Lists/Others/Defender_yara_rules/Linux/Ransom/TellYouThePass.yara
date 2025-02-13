rule Ransom_Linux_TellYouThePass_A7_2147908287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/TellYouThePass.A7"
        threat_id = "2147908287"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "TellYouThePass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {73 00 68 00 6f 00 77 00 6b 00 65 00 79 00 [0-1] 2e 00 74 00 78 00 74 00}  //weight: 4, accuracy: Low
        $x_4_2 = {73 68 6f 77 6b 65 79 [0-1] 2e 74 78 74}  //weight: 4, accuracy: Low
        $x_4_3 = {65 00 6e 00 63 00 66 00 69 00 6c 00 65 00 [0-1] 2e 00 74 00 78 00 74 00}  //weight: 4, accuracy: Low
        $x_4_4 = {65 6e 63 66 69 6c 65 [0-1] 2e 74 78 74}  //weight: 4, accuracy: Low
        $x_1_5 = {52 00 45 00 41 00 44 00 4d 00 45 00 [0-1] 2e 00 68 00 74 00 6d 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_6 = {52 45 41 44 4d 45 [0-1] 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_7 = {52 00 45 00 41 00 44 00 5f 00 4d 00 45 00 [0-1] 2e 00 68 00 74 00 6d 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_8 = {52 45 41 44 5f 4d 45 [0-1] 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_4_9 = ".locked" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*) and 1 of ($x_1_*))) or
            ((4 of ($x_4_*))) or
            (all of ($x*))
        )
}

