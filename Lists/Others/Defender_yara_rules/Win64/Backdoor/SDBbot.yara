rule Backdoor_Win64_SDBbot_A_2147919380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/SDBbot.A"
        threat_id = "2147919380"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "SDBbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "WATAUAVAWH" ascii //weight: 2
        $x_2_2 = "VWATAVAWH" ascii //weight: 2
        $x_2_3 = {83 e0 7f 42 0f b6 0c ?? 0f b6 44 15 ?? 32 c8 88 4c 15 ?? 48 ff c2 48 83 fa ?? 72 e1}  //weight: 2, accuracy: Low
        $x_1_4 = "ABCDEFGHIJKLMNOPn" ascii //weight: 1
        $x_1_5 = "14.121.222.11" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win64_SDBbot_C_2147919383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/SDBbot.C"
        threat_id = "2147919383"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "SDBbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Resource {} is unavailable" ascii //weight: 1
        $x_1_2 = "Could not find resource" ascii //weight: 1
        $x_1_3 = "Failed to commit transaction" ascii //weight: 1
        $x_1_4 = "resource deadlock would occur" ascii //weight: 1
        $x_1_5 = "network unreachable" ascii //weight: 1
        $x_1_6 = "connection already in progress" ascii //weight: 1
        $x_1_7 = "too many files open in system" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

