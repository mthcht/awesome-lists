rule Backdoor_Win32_Nvgra_A_2147599214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nvgra.A"
        threat_id = "2147599214"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nvgra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Visual C++ Runtime Library" ascii //weight: 1
        $x_1_2 = "serv1.alwaysproxy2.info" ascii //weight: 1
        $x_1_3 = "NvGraphicsInterface" ascii //weight: 1
        $x_1_4 = "SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" ascii //weight: 1
        $x_1_5 = "SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\GloballyOpenPorts\\List" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_7 = "StartServiceA" ascii //weight: 1
        $x_1_8 = "OpenSCManagerA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

