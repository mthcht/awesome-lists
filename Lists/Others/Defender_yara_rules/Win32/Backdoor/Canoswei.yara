rule Backdoor_Win32_Canoswei_A_2147648367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Canoswei.A"
        threat_id = "2147648367"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Canoswei"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Autorun.vbs" ascii //weight: 1
        $x_1_2 = "[syn]" ascii //weight: 1
        $x_1_3 = "[floodstop]" ascii //weight: 1
        $x_1_4 = "[halt]" ascii //weight: 1
        $x_1_5 = "Microsoft_Updates_" ascii //weight: 1
        $x_1_6 = ".php?" ascii //weight: 1
        $x_1_7 = "www.weiss-cannon.de" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

