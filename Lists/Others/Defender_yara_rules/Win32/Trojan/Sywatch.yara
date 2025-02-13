rule Trojan_Win32_Sywatch_A_2147641608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sywatch.A"
        threat_id = "2147641608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sywatch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\FileEZ HTTP\\ServiceSample.vbp" wide //weight: 1
        $x_1_2 = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage" wide //weight: 1
        $x_1_3 = "symantecz.com" wide //weight: 1
        $x_1_4 = "/products/downloads/" wide //weight: 1
        $x_1_5 = "net start TasksAnalyser" wide //weight: 1
        $x_1_6 = "*VMWARE*" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

