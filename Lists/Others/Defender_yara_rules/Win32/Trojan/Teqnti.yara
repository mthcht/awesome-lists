rule Trojan_Win32_Teqnti_2147729601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Teqnti"
        threat_id = "2147729601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Teqnti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tequilaboomboom" ascii //weight: 1
        $x_1_2 = "ntdll::strstr(t R1, t 'vmware')" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SysTracer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

