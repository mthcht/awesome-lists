rule Backdoor_Win32_Yordanyan_A_2147729834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Yordanyan.A"
        threat_id = "2147729834"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Yordanyan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&agent_id=" wide //weight: 1
        $x_1_2 = "&agent_file_version=" wide //weight: 1
        $x_1_3 = "Running New Agent and terminating updater!" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = "I'm KeepRunner!" wide //weight: 1
        $x_1_6 = "I'm Updater!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

