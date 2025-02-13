rule Backdoor_Win64_Mondial_A_2147816428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Mondial.A!dha"
        threat_id = "2147816428"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Mondial"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 0f b6 08 b8 ?? ?? ?? ?? 49 ff c0 80 f1 ?? f7 e7 c1 ea 05 b0 64 f6 ea 02 c1 40 2a c7 ff c7 41 88 40 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8d 4c 24 ?? c6 44 24 ?? 41 c6 44 24 ?? 64 c6 44 24 ?? 76 c6 44 24 ?? 61 c6 44 24 ?? 70 c6 44 24 ?? 69 c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e c6 44 24 ?? 64 c6 44 24 ?? 6c c6 44 24 ?? 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 44 24 60 52 c6 44 24 61 65 c6 44 24 62 67 c6 44 24 63 69 c6 44 24 64 73 c6 44 24 65 74 c6 44 24 66 65 c6 44 24 67 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

