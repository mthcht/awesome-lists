rule Backdoor_Win64_Javik_A_2147661511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Javik.A"
        threat_id = "2147661511"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Javik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 0f b7 01 33 c0 66 45 85 c0 74 ?? 66 89 01 66 44 31 41 02 48 8d 41 02 74 0a 48 83 c0 02 66 44 31 00 75 f6 48 8d 41 02}  //weight: 1, accuracy: Low
        $x_1_2 = {44 8a 01 48 8d 41 01 45 84 c0 74 ?? c6 01 00 44 30 41 01 74 08 48 ff c0 44 30 00 75 f8 48 8d 41 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

