rule Trojan_Win32_SuspiciousLogEnumeration_BT_2147951925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspiciousLogEnumeration.BT"
        threat_id = "2147951925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspiciousLogEnumeration"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "-ExecutionPolicy Bypass -Command" wide //weight: 1
        $x_1_3 = "Get-EventLog security -instanceid" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

