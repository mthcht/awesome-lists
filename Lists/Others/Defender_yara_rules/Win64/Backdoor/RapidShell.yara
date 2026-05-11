rule Backdoor_Win64_RapidShell_A_2147969023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/RapidShell.A!dha"
        threat_id = "2147969023"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "RapidShell"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Go build ID: \"" ascii //weight: 10
        $x_1_2 = "h3rs/client/transport.(*Stream).commandHandler" ascii //weight: 1
        $x_1_3 = "h3rs/client/transport.(*Stream).sendOutput" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

