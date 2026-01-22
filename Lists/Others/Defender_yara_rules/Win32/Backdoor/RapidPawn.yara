rule Backdoor_Win32_RapidPawn_A_2147961561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/RapidPawn.A!dha"
        threat_id = "2147961561"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "RapidPawn"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c ping 127.0.0.1 -n 30 > nul && schtasks /run /tn" wide //weight: 1
        $x_1_2 = "Software\\temp" wide //weight: 1
        $x_1_3 = "FBI Should Not Have Launched Trump-Russia Probe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

