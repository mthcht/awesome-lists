rule Backdoor_Win32_RDPdoor_A_2147647161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/RDPdoor.A"
        threat_id = "2147647161"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "RDPdoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" ascii //weight: 2
        $x_4_2 = "PSW: Send flags reseted" ascii //weight: 4
        $x_2_3 = "Kaspersky Anti-Hacker.lnk" ascii //weight: 2
        $x_4_4 = "RNGUV@SD]Lhbsnrngu]Vhoenvr]BtssdouWdsrhno]Sto" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

