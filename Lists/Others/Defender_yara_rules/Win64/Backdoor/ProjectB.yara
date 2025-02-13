rule Backdoor_Win64_ProjectB_A_2147850586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/ProjectB.A"
        threat_id = "2147850586"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "ProjectB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 6f 74 4e 65 74 2e 64 6c 6c 00 44 65 66 61 75 6c 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

