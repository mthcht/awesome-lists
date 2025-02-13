rule Backdoor_Win32_Wonbaful_A_2147686819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wonbaful.A"
        threat_id = "2147686819"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wonbaful"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_cmd_result" wide //weight: 1
        $x_1_2 = "DEL /f /q winmgmt.exe" wide //weight: 1
        $x_1_3 = "netsh firewall add portopening tcp" wide //weight: 1
        $x_1_4 = "TanKuang_" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

