rule Backdoor_Win64_Sombrat_B_2147829952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Sombrat.B"
        threat_id = "2147829952"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Sombrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f af c8 89 d3 80 f3 ae 80 f2 51 f6 c1 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

