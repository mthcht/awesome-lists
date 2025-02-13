rule Backdoor_Win64_UBoatRAT_A_2147724901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/UBoatRAT.A"
        threat_id = "2147724901"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "UBoatRAT"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {64 6f 77 6e 66 69 6c 65 00 00}  //weight: 5, accuracy: High
        $x_5_2 = {75 70 66 69 6c 65 00 00}  //weight: 5, accuracy: High
        $x_5_3 = {62 69 74 73 61 64 6d 69 6e 20 2f 61 64 64 66 69 6c 65 20 [0-16] 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c [0-16] 2e 65 78 65 20 20 25 25 74 65 6d 70 25 25 5c 73 79 73 2e 6c 6f 67}  //weight: 5, accuracy: Low
        $x_1_4 = {2e 00 62 00 61 00 74 00 00 00 00 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 6f 00 70 00 65 00 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = "del %%0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

