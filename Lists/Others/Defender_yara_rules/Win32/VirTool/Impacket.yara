rule VirTool_Win32_Impacket_D_2147897362_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Impacket.D"
        threat_id = "2147897362"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Impacket"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " /c " wide //weight: 1
        $x_1_3 = " /Q " wide //weight: 1
        $x_1_4 = " 1> \\\\127.0.0.1\\ADMIN$\\__" wide //weight: 1
        $x_1_5 = " 2>&1" wide //weight: 1
        $n_10_6 = " netstat -anop TCP" wide //weight: -10
        $n_10_7 = "reg query HK" wide //weight: -10
        $n_10_8 = " chcp.com " wide //weight: -10
        $n_10_9 = "ipconfig /displaydns" wide //weight: -10
        $n_10_10 = "powershell Get-Content" wide //weight: -10
        $n_10_11 = "powershell Get-ChildItem" wide //weight: -10
        $n_10_12 = "mode con:" wide //weight: -10
        $n_10_13 = "Import-Module" wide //weight: -10
        $n_10_14 = "$ErrorActionPreference" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

