rule Trojan_Win32_Dembr_A_2147679932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dembr.A"
        threat_id = "2147679932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dembr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JO840112-" ascii //weight: 1
        $x_1_2 = "shutdown -r -t 0" ascii //weight: 1
        $x_1_3 = "\\\\.\\PhysicalDrive%d" ascii //weight: 1
        $x_1_4 = "taskkill /F /IM pasvc.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

