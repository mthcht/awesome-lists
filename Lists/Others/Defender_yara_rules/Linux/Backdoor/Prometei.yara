rule Backdoor_Linux_Prometei_B_2147943339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Prometei.B!MTB"
        threat_id = "2147943339"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Prometei"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 74 76 52 73 64 43 37 59 71 49 45 58 4b 66 73 49 43 56 73 4b 61 6b 50 2d 30 33 6a 39 2f 56 6c 65 4c 65 62 45 63 32 62 54 59 47 6d 64 69 58 49 54 62 79 78 77 7a 2d 50 62 4f 74 45 75 4d 4e 32 32 72 39 68 77 66 64 48 56 61 6f 6a 65 65 4d 68 33 67 55 70 61 2f 2d 46 71 54 46 41 71 2f 46 72 77 70 58 79 53 45 33 6c 71 32 7a 33 37 58 33 5a 6d 75 34 6a 56 78 53 6a 37 78 74 78 4c 74 50 2d 31 2f 4d 7a 2f 76 2d 66 48 62 68 4f 6a 39 61 78 4c 59 59 67 37 55 78 55 63 39 79 53 53 79 69 49 61 4b 57 43 34 53 32 70 47 52 6f 5f 00}  //weight: 1, accuracy: High
        $x_1_2 = "X3Zmu4jVxSj7xtxLtP-1/Mz/v-fHbhOj9axLYYg7UxUc9ySSyiIaKWC4S2pGRo_" ascii //weight: 1
        $x_1_3 = {00 2f 65 74 63 2f 6f 73 2d 72 65 6c 65 61 73 65 00 63 61 74 20 2f 65 74 63 2f 6f 73 2d 72 65 6c 65 61 73 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

