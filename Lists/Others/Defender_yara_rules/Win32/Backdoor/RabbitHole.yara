rule Backdoor_Win32_RabbitHole_A_2147645751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/RabbitHole.A"
        threat_id = "2147645751"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "RabbitHole"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/GetActiveCommands" ascii //weight: 1
        $x_1_2 = "/IssueCommand" ascii //weight: 1
        $x_5_3 = "StartKeylogger" ascii //weight: 5
        $x_5_4 = "RabbitHole" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

