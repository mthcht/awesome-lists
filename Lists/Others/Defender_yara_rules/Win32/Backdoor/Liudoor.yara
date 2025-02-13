rule Backdoor_Win32_Liudoor_A_2147705688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Liudoor.A!dha"
        threat_id = "2147705688"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Liudoor"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 76 63 48 6f 73 74 44 4c 4c 3a 20 53 65 72 76 69 63 65 4d 61 69 6e 20 64 6f 6e 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 76 63 48 6f 73 74 44 4c 4c 3a 20 52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 43 74 72 6c 48 61 6e 64 6c 65 72 20 25 53 20 66 61 69 6c 65 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 76 63 48 6f 73 74 44 4c 4c 3a 20 53 65 72 76 69 63 65 4d 61 69 6e 28 25 64 2c 20 25 73 29 20 63 61 6c 6c 65 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 76 63 48 6f 73 74 44 4c 4c 3a 20 53 65 72 76 69 63 65 48 61 6e 64 6c 65 72 20 63 61 6c 6c 65 64 20 53 45 52 56 49 43 45 5f 43 4f 4e 54 52 4f 4c 5f 53 48 55 54 44 4f 57 4e 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 76 63 48 6f 73 74 44 4c 4c 3a 20 53 65 72 76 69 63 65 48 61 6e 64 6c 65 72 20 63 61 6c 6c 65 64 20 53 45 52 56 49 43 45 5f 43 4f 4e 54 52 4f 4c 5f 49 4e 54 45 52 52 4f 47 41 54 45 00}  //weight: 1, accuracy: High
        $x_1_6 = {53 76 63 48 6f 73 74 44 4c 4c 3a 20 53 65 72 76 69 63 65 48 61 6e 64 6c 65 72 20 63 61 6c 6c 65 64 20 53 45 52 56 49 43 45 5f 43 4f 4e 54 52 4f 4c 5f 43 4f 4e 54 49 4e 55 45 00}  //weight: 1, accuracy: High
        $x_1_7 = {53 76 63 48 6f 73 74 44 4c 4c 3a 20 53 65 72 76 69 63 65 48 61 6e 64 6c 65 72 20 63 61 6c 6c 65 64 20 53 45 52 56 49 43 45 5f 43 4f 4e 54 52 4f 4c 5f 50 41 55 53 45 00}  //weight: 1, accuracy: High
        $x_1_8 = {53 76 63 48 6f 73 74 44 4c 4c 3a 20 53 65 72 76 69 63 65 48 61 6e 64 6c 65 72 20 63 61 6c 6c 65 64 20 53 45 52 56 49 43 45 5f 43 4f 4e 54 52 4f 4c 5f 53 54 4f 50 00}  //weight: 1, accuracy: High
        $x_2_9 = {73 76 63 68 6f 73 74 64 6c 6c 73 65 72 76 65 72 2e 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_1_10 = {44 69 67 69 74 61 6c 4c 69 73 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Liudoor_B_2147705689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Liudoor.B!dha"
        threat_id = "2147705689"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Liudoor"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 76 63 68 6f 73 74 64 6c 6c 73 65 72 76 65 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 75 63 63 00 00 00 00 46 61 69 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {55 8b ee 81 ed ?? ?? ?? ?? 8a 84 2a ?? ?? ?? ?? 8b fe 34 1f 83 c9 ff 88 82 ?? ?? ?? ?? 33 c0 42 f2 ae f7 d1 49 3b d1 72 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

