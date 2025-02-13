rule Backdoor_Win64_SignJoinLoader_A_2147851919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/SignJoinLoader.A"
        threat_id = "2147851919"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "SignJoinLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4f 44 53 65 63 75 72 69 74 79 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 6d 73 78 6d 6c 33 2e 64 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

