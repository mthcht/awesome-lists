rule Trojan_Win32_Usbint_A_2147597199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Usbint.A"
        threat_id = "2147597199"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Usbint"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\TENCENT\\PLATFORM_TYPE_LIST" ascii //weight: 1
        $x_1_3 = "TIMPlatform.exe" ascii //weight: 1
        $x_1_4 = "Drivers\\usbinte.sys" ascii //weight: 1
        $x_1_5 = "exefile\\shell\\open\\command" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

