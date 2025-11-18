rule Backdoor_Win64_EggStremeAgent_B_2147957656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/EggStremeAgent.B!dha"
        threat_id = "2147957656"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "EggStremeAgent"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 77 44 51 59 4a 4b 6f 5a 49 68 76 63 4e 41 51 45 4c 42 51 41 77 54 54 45 4a 4d 41 63 47 41 31 55 45 42 68 4d 41 4d 51 6b 77 0a 42 77 59 44 56 51 51 49 45 77 41 78 43 54 41 48 42 67 4e 56 42 41 63 54 41 44 45 4a 4d 41 63 47 41 31 55 45 43 52 4d 41 4d 51 6b 77 42 77 59 44 56 51 51 52 45 77 41 78 43 54 41 48 42 67 4e 56 0a 42 41 6f 54 41 44 45 4a 4d 41 63 47 41 31 55 45 43 78 4d 41 4d 43 41 58 44 54 45 35 4d 54 45 77 4e 6a 41 31 4d 7a 49 79 4d 6c 6f 59 44 7a 63 30 4f 54 67 77 4e 7a 45 78 4d 54 41 30 4e 54 49 79 0a 57 6a 42 4e 4d 51 6b 77 42 77 59 44 56 51 51 47 45 77 41 78 43 54 41 48 42 67 4e 56 42 41 67 54 41 44 45 4a 4d 41 63 47 41 31 55 45 42 78 4d 41 4d 51 6b 77 42 77 59 44 56 51 51 4a 45 77 41 78 0a}  //weight: 1, accuracy: High
        $x_1_2 = {5b 2a 5d 20 25 2d 31 36 73 25 64 20 20 6f 70 65 6e 0a}  //weight: 1, accuracy: High
        $x_1_3 = "processid is invalid." ascii //weight: 1
        $x_1_4 = " %s%sUSERNAME" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

