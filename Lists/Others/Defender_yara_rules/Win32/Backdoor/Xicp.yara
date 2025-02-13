rule Backdoor_Win32_Xicp_A_2147679759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Xicp.A"
        threat_id = "2147679759"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Xicp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C84D4C44-E304-41ad-8EDE-F2618DCC3605" wide //weight: 1
        $x_1_2 = "Netfilter" wide //weight: 1
        $x_1_3 = "mcdonaldss.xicp.net" ascii //weight: 1
        $x_1_4 = "WorkMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

