rule Trojan_Win32_SysEnum_Z_2147943073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SysEnum.Z!MTB"
        threat_id = "2147943073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SysEnum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "systeminfo" wide //weight: 1
        $x_1_2 = "wmic logicaldisk" wide //weight: 1
        $x_1_3 = "net user guest" wide //weight: 1
        $x_1_4 = "net user administrator" wide //weight: 1
        $x_1_5 = "netsh firewall show state" wide //weight: 1
        $x_1_6 = "tasklist /svc" wide //weight: 1
        $x_1_7 = "ipconfig/all " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

