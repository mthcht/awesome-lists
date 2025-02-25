rule Trojan_Win32_SuspRdpConfig_ZPA_2147934409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRdpConfig.ZPA"
        threat_id = "2147934409"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRdpConfig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " add " wide //weight: 1
        $x_1_2 = "System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" wide //weight: 1
        $x_1_3 = "/v PortNumber " wide //weight: 1
        $x_1_4 = "/t REG_DWORD /d " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspRdpConfig_ZPB_2147934410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRdpConfig.ZPB"
        threat_id = "2147934410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRdpConfig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "netsh" wide //weight: 1
        $x_1_2 = "advfirewall firewall add rule name=" wide //weight: 1
        $x_1_3 = "RDPPORTLatest-TCP-In" wide //weight: 1
        $x_1_4 = "dir=in action=allow protocol=TCP localport=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspRdpConfig_ZPB_2147934410_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRdpConfig.ZPB"
        threat_id = "2147934410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRdpConfig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " add " wide //weight: 1
        $x_1_2 = "\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" wide //weight: 1
        $x_1_3 = "/v UserAuthentication /d 0 " wide //weight: 1
        $x_1_4 = "/t REG_DWORD" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

