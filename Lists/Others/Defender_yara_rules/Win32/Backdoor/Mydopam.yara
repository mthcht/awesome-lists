rule Backdoor_Win32_Mydopam_A_2147595193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mydopam.gen!A"
        threat_id = "2147595193"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mydopam"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {67 6f 74 6f 20 74 72 79 0d 0a 64 65 6c 20 43 3a 5c 54 45 4d 50 5c 6d 73 69 64 65 6c 2e 62 61 74}  //weight: 2, accuracy: High
        $x_2_2 = {48 54 54 50 1a 0f 0f 57 57 57 0e 53 50 41 4d 43 41 54 43 48 45 52 4f 0e 42 49 5a 0f 44 4c 0f 42 4f 54 0e 44 4c 4c}  //weight: 2, accuracy: High
        $x_2_3 = {2a 48 54 54 50 1a 0f 0f 49 46 52 41 4d 45 42 49 5a 2e 43 4f 4d 2e 45 58 45 2e 50 48 50 2e 55 49 44 2e}  //weight: 2, accuracy: High
        $x_1_4 = "Software\\Microsoft\\Security Center" ascii //weight: 1
        $x_1_5 = {46 69 72 65 77 61 6c 6c 4f 76 65 72 72 69 64 65 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 46 69 72 65 77 61 6c 6c 44 69 73 61 62 6c 65 4e 6f 74 69 66 79}  //weight: 1, accuracy: High
        $x_1_6 = {40 65 63 68 6f 20 6f 66 66 0d 0a 3a 74 72 79 0d 0a 64 65 6c 20 25 73 0d 0a 69 66 20 65 78 69 73 74 20 25 73 20 67 6f 74 6f 20 74 72 79 0d 0a 64 65 6c 20 25 73 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

