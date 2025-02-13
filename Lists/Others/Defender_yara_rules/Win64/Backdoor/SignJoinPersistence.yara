rule Backdoor_Win64_SignJoinPersistence_A_2147851920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/SignJoinPersistence.A"
        threat_id = "2147851920"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "SignJoinPersistence"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4f 6e 65 44 72 69 76 65 53 72 76 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

