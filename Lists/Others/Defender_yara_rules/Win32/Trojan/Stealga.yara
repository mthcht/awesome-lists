rule Trojan_Win32_Stealga_DA_2147938208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealga.DA!MTB"
        threat_id = "2147938208"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealga"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System Info" wide //weight: 1
        $x_1_2 = "wmic logicaldisk" wide //weight: 1
        $x_1_3 = "Administrator User Info" wide //weight: 1
        $x_1_4 = "net user administrator" wide //weight: 1
        $x_1_5 = "tasklist /svc" wide //weight: 1
        $x_1_6 = "ipconfig/all" wide //weight: 1
        $x_1_7 = "netstat -ano" wide //weight: 1
        $x_1_8 = "netsh firewall show" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

