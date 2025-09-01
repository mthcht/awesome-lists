rule Trojan_Win32_KillAV_SA_2147808492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillAV.SA"
        threat_id = "2147808492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillAV"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\release\\killav.pdb" ascii //weight: 10
        $x_1_2 = "msmpeng.exe" ascii //weight: 1
        $x_1_3 = "sentinelagent.exe" ascii //weight: 1
        $x_1_4 = "alsvc.exe" ascii //weight: 1
        $x_1_5 = "mctray.exe" ascii //weight: 1
        $x_1_6 = "savservice.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_KillAV_SA_2147808492_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillAV.SA"
        threat_id = "2147808492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillAV"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c del" ascii //weight: 1
        $x_1_2 = "\\\\.\\aswsp_arpot2" ascii //weight: 1
        $x_1_3 = "\\\\.\\aswsp_avar" ascii //weight: 1
        $x_1_4 = "deviceiocontrol" ascii //weight: 1
        $x_1_5 = "createtoolhelp32snapshot" ascii //weight: 1
        $x_1_6 = "process32firstw" ascii //weight: 1
        $x_1_7 = "process32nextw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillAV_A_2147834222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillAV.A!MTB"
        threat_id = "2147834222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /f /im msinfo.exe" ascii //weight: 1
        $x_1_2 = "taskkill /f /im rundll32.exe" ascii //weight: 1
        $x_1_3 = "wmic.exe product where \"name like '%Eset%'\" call uninstall /nointeractive" ascii //weight: 1
        $x_1_4 = "wmic.exe product where \"name like '%%Kaspersky%%'\" call uninstall /nointeractive" ascii //weight: 1
        $x_1_5 = "wmic.exe product where \"name like '%avast%'\" call uninstall /nointeractive" ascii //weight: 1
        $x_1_6 = "wmic.exe product where \"name like '%avp%'\" call uninstall /nointeractive" ascii //weight: 1
        $x_1_7 = "wmic.exe product where \"name like '%Security%'\" call uninstall /nointeractive" ascii //weight: 1
        $x_1_8 = "wmic.exe product where \"name like '%AntiVirus%'\" call uninstall /nointeractive" ascii //weight: 1
        $x_1_9 = "wmic.exe product where \"name like '%Norton Security%'\" call uninstall /nointeractive" ascii //weight: 1
        $x_1_10 = "netsh advfirewall firewall delete rule name=\"tcp all\" dir=in" ascii //weight: 1
        $x_1_11 = "netsh advfirewall firewall delete rule name=\"tcpall\" dir=out" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillAV_EM_2147951023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillAV.EM!MTB"
        threat_id = "2147951023"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {39 4d 0c 76 10 8b 45 08 8a 55 10 03 c1 28 10 41 3b 4d 0c 72 f0}  //weight: 3, accuracy: High
        $x_1_2 = "Recycler\\aa.txt" ascii //weight: 1
        $x_1_3 = "AntivusType = %d ProcessName = %s" ascii //weight: 1
        $x_1_4 = "Begin Write ShellCode File" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

