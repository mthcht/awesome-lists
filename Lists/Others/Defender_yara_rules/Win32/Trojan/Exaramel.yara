rule Trojan_Win32_Exaramel_A_2147730375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Exaramel.A"
        threat_id = "2147730375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Exaramel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wsmprovav.exe" wide //weight: 1
        $x_1_2 = "Windows Check AV service" wide //weight: 1
        $x_1_3 = "/settings/proxy/@password" wide //weight: 1
        $x_1_4 = "SYSTEM\\CurrentControlSet\\Services" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

