rule Backdoor_Win32_Domork_A_2147620608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Domork.A"
        threat_id = "2147620608"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Domork"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "software\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Classes\\HTTP\\shell\\open\\command" ascii //weight: 1
        $x_1_3 = "SYSTEM\\ControlSet001\\Services\\%s" ascii //weight: 1
        $x_1_4 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 00}  //weight: 1, accuracy: High
        $x_1_5 = "DoMainWork" ascii //weight: 1
        $x_1_6 = "mythreadid=%d;myserveraddr=%s;myserverport=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

