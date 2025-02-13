rule Backdoor_Win64_SignJoinInstaller_A_2147851918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/SignJoinInstaller.A"
        threat_id = "2147851918"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "SignJoinInstaller"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 03 48 8b [0-6] 48 d3 ea 48 8b ca 0f b6 c9 33 c1}  //weight: 1, accuracy: Low
        $n_1_2 = {4f 44 53 65 63 75 72 69 74 79 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 6d 73 78 6d 6c 33 2e 64 6c 6c}  //weight: -1, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

