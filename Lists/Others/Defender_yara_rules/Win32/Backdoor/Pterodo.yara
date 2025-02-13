rule Backdoor_Win32_Pterodo_A_2147720203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Pterodo.A"
        threat_id = "2147720203"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Pterodo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 73 66 6f 6c 64 65 72 3d 7b 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 6f 6d 6d 61 6e 64 3d 7b 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 70 68 70 [0-6] 00 50 4f 53 54}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 64 65 76 65 6c 6f 70 5c 72 65 61 64 79 5c [0-80] 5c 77 69 6e 72 65 73 74 6f 72 65 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

