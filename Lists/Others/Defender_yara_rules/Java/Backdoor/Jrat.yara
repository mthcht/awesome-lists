rule Backdoor_Java_Jrat_C_2147707687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Java/Jrat.C"
        threat_id = "2147707687"
        type = "Backdoor"
        platform = "Java: Java binaries (classes)"
        family = "Jrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {0c 0e 4f 0f 45 09 58 1f 4f 52 4e 1d 5e}  //weight: 4, accuracy: High
        $x_4_2 = {0e 0f 5e 09 48 1f 45 12 4c 15 4d 52 5e 04 5e}  //weight: 4, accuracy: High
        $x_1_3 = {0d 41 4c 4c 41 54 4f 52 49 78 44 45 4d 4f}  //weight: 1, accuracy: High
        $x_1_4 = "/bridj/jawt/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Java_Jrat_C_2147707687_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Java/Jrat.C"
        threat_id = "2147707687"
        type = "Backdoor"
        platform = "Java: Java binaries (classes)"
        family = "Jrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {05 37 37 24 4e 5a}  //weight: 1, accuracy: High
        $x_1_2 = {0d 11 07 10 0d 16 10 c0 80 07 4d 06 02 16}  //weight: 1, accuracy: High
        $x_1_3 = {0a 64 65 63 6f 6d 70 72 65 73 73}  //weight: 1, accuracy: High
        $x_1_4 = {11 63 6f 6e 66 69 67 2f 42 79 74 65 4c 6f 61 64 65 72}  //weight: 1, accuracy: High
        $x_5_5 = {84 03 ff 1c 82 92 55 1d 9b 00 16 2b 2a 1d 84 03 ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Java_Jrat_C_2147707687_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Java/Jrat.C"
        threat_id = "2147707687"
        type = "Backdoor"
        platform = "Java: Java binaries (classes)"
        family = "Jrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 50 49 4e 47 52 45 53 50 4f 4e 53 45}  //weight: 1, accuracy: High
        $x_1_2 = {08 53 54 41 52 54 43 41 4d}  //weight: 1, accuracy: High
        $x_1_3 = {0a 4f 46 46 4c 49 4e 45 4c 4f 47}  //weight: 1, accuracy: High
        $x_1_4 = {08 45 58 50 4c 4f 52 45 52}  //weight: 1, accuracy: High
        $x_1_5 = {09 49 4e 4a 45 43 54 4a 41 52}  //weight: 1, accuracy: High
        $x_1_6 = {0d 4c 4f 41 44 50 52 4f 43 45 53 53 45 53}  //weight: 1, accuracy: High
        $x_5_7 = {0b 48 65 61 64 65 72 2e 6a 61 76 61}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Java_Jrat_C_2147707687_3
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Java/Jrat.C"
        threat_id = "2147707687"
        type = "Backdoor"
        platform = "Java: Java binaries (classes)"
        family = "Jrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {14 4c 66 75 7a 7a 6c 65 2f 42 43 4a 49 6e 6a 65 63 74 6f 72 3b}  //weight: 1, accuracy: High
        $x_4_2 = {11 4c 63 6f 6e 66 69 67 2f 52 65 67 69 73 74 72 79 3b}  //weight: 4, accuracy: High
        $x_1_3 = {13 4c 63 6f 6e 66 69 67 2f 42 79 74 65 4c 6f 61 64 65 72 3b}  //weight: 1, accuracy: High
        $x_4_4 = {0d 63 6f 6e 66 69 67 2f 52 65 61 64 49 4f}  //weight: 4, accuracy: High
        $x_1_5 = {07 5d 15 44 18 45 0b 59}  //weight: 1, accuracy: High
        $x_1_6 = {06 14 43 18 4e 19 44}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Java_Jrat_C_2147707687_4
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Java/Jrat.C"
        threat_id = "2147707687"
        type = "Backdoor"
        platform = "Java: Java binaries (classes)"
        family = "Jrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/jstealth/api/loaders/CCLoader" ascii //weight: 1
        $x_1_2 = "/jstealth/api/ClientPlugin" ascii //weight: 1
        $x_1_3 = {14 4a 61 72 49 6e 6a 65 63 74 55 70 6c 6f 61 64 2e 6a 61 76 61}  //weight: 1, accuracy: High
        $x_1_4 = "net/oscp/client/jarinjector/JarInjectUpload" ascii //weight: 1
        $x_1_5 = {0e 63 72 65 61 74 65 54 65 6d 70 46 69 6c 65}  //weight: 1, accuracy: High
        $x_1_6 = {04 2e 6a 61 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Java_Jrat_F_2147712342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Java/Jrat.F"
        threat_id = "2147712342"
        type = "Backdoor"
        platform = "Java: Java binaries (classes)"
        family = "Jrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 65 4a 7c 47 7d 74 41}  //weight: 1, accuracy: High
        $x_1_2 = {0c 53 40 6c 55 71 53 6e 74 6a 5e 46 61}  //weight: 1, accuracy: High
        $x_1_3 = {0d 42 42 60 46 7c 57 6d 45 7d 4f 76 66 40}  //weight: 1, accuracy: High
        $x_1_4 = {0b 61 46 60 55 77 51 6d 53 73 77 5a}  //weight: 1, accuracy: High
        $x_1_5 = {1a 21 27 59 75 16 75 6a 5c 03 71 4f 73 50 61 23 67 77 5b 6f 1c 60 5e 62 41 50 32}  //weight: 1, accuracy: High
        $x_1_6 = {04 56 67 6a 56}  //weight: 1, accuracy: High
        $x_1_7 = {06 62 46 77 40 4a 70}  //weight: 1, accuracy: High
        $x_1_8 = {11 0e 3a 31 2f 2c 09 13 2e 17 04 1b 1b 56 30 46 7e 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

