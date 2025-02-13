rule Trojan_Win32_PTASpy_A_2147895609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PTASpy.A"
        threat_id = "2147895609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PTASpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\PTASpy\\PTASpy.csv" ascii //weight: 5
        $x_1_2 = "LogonUserW" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "GetCurrentProcess" ascii //weight: 1
        $x_1_5 = "CryptBinaryToStringW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

