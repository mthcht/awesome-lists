rule Backdoor_Win64_KuboShell_DA_2147982871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/KuboShell.DA!MTB"
        threat_id = "2147982871"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "KuboShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {69 4f 6a 45 34 4d 54 45 77 4e 7a 59 79 4e 7a 52 39 2e 43 7a 69 73 66 67 61 35 6a 43 6a 35 65 54 7a 79 4e 4f 70 71 4b 36 4c 6e 54 50 53 36 65 5f 7a 38 4e 77 73 39 53 4f 31 32 67 5f 67 00 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

