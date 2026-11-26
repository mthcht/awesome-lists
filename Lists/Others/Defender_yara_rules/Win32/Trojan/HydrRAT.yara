rule Trojan_Win32_HydrRAT_2147982851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HydrRAT!atmn"
        threat_id = "2147982851"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HydrRAT"
        severity = "Critical"
        info = "atmn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "NETMAL:adapter_disable|OK" ascii //weight: 3
        $x_3_2 = "NETMAL:drivers_remove|OK" ascii //weight: 3
        $x_2_3 = "sc config WlanAutoConfig start=disabled >nul 2>&1" ascii //weight: 2
        $x_2_4 = "netsh wlan delete profile name=* i=* >nul 2>&1" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

