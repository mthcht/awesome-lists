rule Trojan_Win32_TurlaCarbonInjector_2147849685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurlaCarbonInjector"
        threat_id = "2147849685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurlaCarbonInjector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinResSvc" ascii //weight: 1
        $x_1_2 = "C:\\Program Files\\Windows NT\\MSSVCCFG.dll" ascii //weight: 1
        $x_1_3 = "Failed to set up service. Error code: %d" ascii //weight: 1
        $x_1_4 = "VirtualQuery failed for %d bytes at address %p" ascii //weight: 1
        $x_1_5 = "VirtualProtect failed with code 0x%x" ascii //weight: 1
        $x_1_6 = "%p not found?!?!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

