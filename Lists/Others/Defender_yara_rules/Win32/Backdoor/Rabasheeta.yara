rule Backdoor_Win32_Rabasheeta_A_2147664983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rabasheeta.A"
        threat_id = "2147664983"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rabasheeta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 61 6b 65 53 68 69 74 61 72 61 62 61 54 68 72 65 61 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {62 69 6e 44 6f 77 6e 6c 6f 61 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {4b 41 4b 49 4b 4f 5f 4c 45 4e 5f 4c 49 4d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

