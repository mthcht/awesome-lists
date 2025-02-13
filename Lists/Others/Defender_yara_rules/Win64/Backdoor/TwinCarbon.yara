rule Backdoor_Win64_TwinCarbon_B_2147925254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/TwinCarbon.B!dha"
        threat_id = "2147925254"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "TwinCarbon"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DoUpdateInstanceEx" ascii //weight: 1
        $x_1_2 = "get_file" ascii //weight: 1
        $x_1_3 = "put_file" ascii //weight: 1
        $x_1_4 = "sleep" ascii //weight: 1
        $x_1_5 = "close" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

