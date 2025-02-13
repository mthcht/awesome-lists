rule Backdoor_Win64_Noratops_A_2147723365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Noratops.A!dha"
        threat_id = "2147723365"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Noratops"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 25 00 53 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 70 00 75 00 62 00 6c 00 69 00 63 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 25 00 63 00 25 00 78 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 00 4a 00 6f 00 62 00 20 00 53 00 61 00 76 00 65 00 20 00 2f 00 20 00 4c 00 6f 00 61 00 64 00 20 00 43 00 6f 00 6e 00 66 00 69 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 00 6e 00 74 00 75 00 73 00 65 00 72 00 2e 00 64 00 61 00 74 00 2e 00 73 00 77 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "Are you sure to delete this record ?" wide //weight: 1
        $x_1_6 = "sdrsrv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

