rule Ransom_Linux_Erebus_B_2147772494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Erebus.B!MTB"
        threat_id = "2147772494"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Erebus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 65 74 63 2f 72 63 2e 64 2f 72 63 32 2e 64 2f [0-4] 62 6c 75 65 74 6f 6f 74 68}  //weight: 1, accuracy: Low
        $x_1_2 = {59 6f 75 72 20 66 69 6c 65 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2e [0-5] 50 6c 65 61 73 65 20 63 68 65 63 6b 20 5f 44 45 43 52 59 50 54 5f 46 49 4c 45 2e 74 78 74 20 5f 44 45 43 52 59 50 54 5f 46 49 4c 45 2e 68 74 6d 6c 20 66 69 6c 65 20 69 6e 20 73 61 6d 65}  //weight: 1, accuracy: Low
        $x_1_3 = {53 43 41 4e 5b 25 64 5d 5b 25 73 5d [0-2] 53 41 56 45 5b 25 73 5d}  //weight: 1, accuracy: Low
        $x_1_4 = {2f 65 74 63 2f 63 72 6f 6e 2e 68 6f 75 72 6c 79 2f [0-2] 61 6e 61 63 72 6f 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {68 74 74 70 3a [0-16] 25 73 [0-16] 2f 70 75 72 63 68 61 73 65 3f 6d 69 64}  //weight: 1, accuracy: Low
        $x_1_6 = "To decrypt your files please visit the following website:" ascii //weight: 1
        $x_1_7 = "EREBUS IS BEST" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

