rule Backdoor_Linux_Apmod_A_2147678488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Apmod.gen!A"
        threat_id = "2147678488"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Apmod"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BAN_USERAGENT" ascii //weight: 1
        $x_1_2 = "CHECK_BOT_USERAGENT" ascii //weight: 1
        $x_1_3 = "CHECK_RAW_COOKIE" ascii //weight: 1
        $x_1_4 = "SE_REFERER" ascii //weight: 1
        $x_1_5 = "TAGS_FOR_INJECT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Apmod_A_2147717418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Apmod.A"
        threat_id = "2147717418"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Apmod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6d 6f 64 5f [0-16] 2e 63 00 2e 00 2e 74 6d 70 00 25 73 20 31 3e 25 73 00 72 00 25 73 20 31 3e 25 73 20 32 3e 2f 64 65 76 2f 6e 75 6c 6c 00 25 73 20 31 3e 3e 25 73 20 32 3e 2f 64 65 76 2f 6e 75 6c 6c 00 [0-8] 65 63 68 6f 20 2d 6e 20 25 73 20 7c 20 6d 64 35 73 75 6d 20 7c 20 61 77 6b 20 27 7b 70 72 69 6e 74 20 24 31 7d 27 00 25 69 0a 25 73 [0-20] 2f 76 61 72 2f 72 75 6e 2f 75 74 6d 70 00 2f 64 65 76 2f 00}  //weight: 3, accuracy: Low
        $x_1_2 = {61 70 5f 68 6f 6f 6b 5f 69 6e 73 65 72 74 5f 66 69 6c 74 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {61 70 5f 72 65 67 69 73 74 65 72 5f 6f 75 74 70 75 74 5f 66 69 6c 74 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Apmod_A_2147824588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Apmod.A!xp"
        threat_id = "2147824588"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Apmod"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 89 c0 41 89 c9 41 89 ca 41 c1 e8 0b 41 c1 e2 04 41 c1 e9 05 41 83 e0 03 45 31 d1 46 8b 04 86 41 01 c9 41 01 c0 05 47 86 c8 61 45 31 c8 44 29 c2 49 89 c0 41 83 e0 03 41 89 d1 41 89 d2 46 8b 04 86 41 c1 e9 05 41 c1 e2 04 45 31 d1 41 01 d1 41 01 c0 45 31 c8 44 29 c1 85 c0}  //weight: 1, accuracy: High
        $x_1_2 = {31 c0 48 85 ff 74 5c 31 f6 45 31 c0 31 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

