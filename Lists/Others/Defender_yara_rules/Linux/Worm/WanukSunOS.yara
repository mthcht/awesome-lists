rule Worm_Linux_WanukSunOS_A_2147793494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Linux/WanukSunOS.A!MTB"
        threat_id = "2147793494"
        type = "Worm"
        platform = "Linux: Linux platform"
        family = "WanukSunOS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "W O R M S    A G A I N S T    N U C L E A R    K I L L E R S" ascii //weight: 2
        $x_1_2 = "Your System Has Been Officically WANKed" ascii //weight: 1
        $x_1_3 = {72 6d 20 2d 66 20 25 73 3b [0-2] 75 75 64 65 63 6f 64 65 20 25 73 2e 75 75 65 3b [0-2] 63 68 6d 6f 64 20 35 35 35 20 25 73 3b [0-2] 72 6d 20 2d 66 20 2e 2a 2e 75 75 65 3b [0-2] 74 6f 75 63 68 20 2d 74 20 31 39 38 38 31 31 30 32 31 37 30 30 20 25 73 20 2e 3b [0-2] 77 63 20 2d 63 20 25 73}  //weight: 1, accuracy: Low
        $x_1_4 = {2f 75 73 72 2f 62 69 6e 2f 63 72 6f 6e 74 61 62 20 2d 6c 20 7c 20 67 72 65 70 20 2d 76 20 27 52 65 73 74 61 72 74 69 6e 67 20 73 63 68 65 64 75 6c 65 72 20 64 61 65 6d 6f 6e 27 20 7c 20 67 72 65 70 20 2d 76 20 27 25 73 27 20 3e 20 2e 63 72 6f 6e 74 61 62 3b [0-2] 63 70 20 2d 66 70 20 25 73 20 25 73 3b [0-2] 63 68 6d 6f 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

