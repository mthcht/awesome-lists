rule Backdoor_Win64_Negetsog_C_2147895437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Negetsog.C!dha"
        threat_id = "2147895437"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Negetsog"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ingram nielson mandel meadows lovell" ascii //weight: 1
        $x_1_2 = "dee6ce91473dafff" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

