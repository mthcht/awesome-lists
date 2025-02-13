rule Trojan_Win32_Fordan_A_2147625061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fordan.A"
        threat_id = "2147625061"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fordan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Administrator\\Desktop\\SysStartUp\\Project1.vbp" wide //weight: 1
        $x_1_2 = "Win32:virus.AlbaNet.a" wide //weight: 1
        $x_1_3 = "Error occured You was Lucky" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

