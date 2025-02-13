rule Trojan_Win32_Goriadu_AA_2147635927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Goriadu.AA!dll"
        threat_id = "2147635927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Goriadu"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Update-Lock-3faf98" ascii //weight: 1
        $x_1_2 = ".l0086.com.cn" ascii //weight: 1
        $x_1_3 = ".02l.cn" ascii //weight: 1
        $x_1_4 = "c:\\log-server-1.txt" ascii //weight: 1
        $x_1_5 = "www.010com.cn/count" ascii //weight: 1
        $x_1_6 = "\\MyToolsHelp\\" ascii //weight: 1
        $x_1_7 = "cmssc.dll" ascii //weight: 1
        $x_1_8 = "u.gogle.cn/default" ascii //weight: 1
        $x_1_9 = "\\baidu\\tohome.exe" ascii //weight: 1
        $x_1_10 = {5c 4d 79 49 45 44 61 74 61 5c 00 00 53 79 73}  //weight: 1, accuracy: High
        $x_1_11 = {62 72 75 64 6f 2e 64 61 74 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Goriadu_C_2147638077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Goriadu.C"
        threat_id = "2147638077"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Goriadu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\MyToolsHelp\\" ascii //weight: 1
        $x_2_2 = "%s\\SN1_%d_%d.log" ascii //weight: 2
        $x_2_3 = "sp_regtable_mutex32" ascii //weight: 2
        $x_3_4 = "SYSTEM\\CurrentControlSet\\Services\\WinSock2\\speednet_sph" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

