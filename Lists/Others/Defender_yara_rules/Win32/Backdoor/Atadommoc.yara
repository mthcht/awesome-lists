rule Backdoor_Win32_Atadommoc_A_2147634090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Atadommoc.A"
        threat_id = "2147634090"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Atadommoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6f 6d 6d 6f 6e 2e 64 61 74 61 [0-3] 30 43 37 46 46 31 36 43 2d 33 38 45 33 2d 31 31 64 30 2d 39 37 41 42 2d 30 30 43 30 34 46 43 32 41 44 39 38}  //weight: 1, accuracy: Low
        $x_1_2 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73 [0-10] 57 69 6e 73 74 61 30 5c 44 65 66 61 75 6c 74 [0-10] 73 76 63 68 6f 73 74 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {53 74 61 72 74 69 6e 67 20 64 72 69 76 65 72 20 25 73 [0-10] 44 65 63 72 79 70 74 69 6e 67 20 25 73 [0-10] 44 6f 77 6e 6c 6f 61 64 69 6e 67 20 25 73}  //weight: 1, accuracy: Low
        $x_1_4 = {25 73 20 63 6c 69 65 6e 74 20 73 74 6f 70 70 65 64 [0-10] 25 73 20 63 6c 69 65 6e 74 20 73 74 61 72 74 65 64 [0-10] 65 78 65 [0-10] 31 37 38 2e 31 37 2e 31 36 33 2e 31 30 36}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Atadommoc_B_2147641428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Atadommoc.B"
        threat_id = "2147641428"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Atadommoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 16 6a 35 68 90 1f 00 00 57 ff 75 ?? 8b c8 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {74 14 6a 35 68 91 1f 00 00 56 53 8b c8 e8}  //weight: 1, accuracy: High
        $x_2_3 = "common.data" ascii //weight: 2
        $x_1_4 = "Job::Decrypt" ascii //weight: 1
        $x_1_5 = "CODE_SNAP()" ascii //weight: 1
        $x_1_6 = "ForkInSpool():" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Atadommoc_C_2147647287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Atadommoc.C"
        threat_id = "2147647287"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Atadommoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 45 17 8d 04 37 c0 20 04 8a 10 8a cb 80 e9 30 80 f9 09 77 06 0a ca 88 08 eb 11 8a cb 80 e9 61 80 f9 05 77 2f 80 eb 57}  //weight: 1, accuracy: High
        $x_1_2 = {ff 4d fc c6 00 e9 89 48 01 75}  //weight: 1, accuracy: High
        $x_1_3 = {63 6f 6d 6d 6f 6e 2e 64 61 74 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

