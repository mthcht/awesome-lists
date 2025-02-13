rule Trojan_Win32_Cutrinka_A_2147620366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cutrinka.A"
        threat_id = "2147620366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutrinka"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Service Host Manager" ascii //weight: 1
        $x_1_2 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 1
        $x_1_3 = "\"KATRINA Virus\"!" ascii //weight: 1
        $x_1_4 = "\\System32\\shutdown.exe" wide //weight: 1
        $x_1_5 = "\\system32\\sevcst.exe" wide //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

