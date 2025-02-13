rule Trojan_Win32_TurlaCarbonRootkit_2147849793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurlaCarbonRootkit"
        threat_id = "2147849793"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurlaCarbonRootkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Device\\gusb" wide //weight: 1
        $x_1_2 = "\\DosDevices\\gusb" wide //weight: 1
        $x_1_3 = "\\??\\C:\\Windows\\msnsvcx64.dll" wide //weight: 1
        $x_1_4 = "gusb.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

