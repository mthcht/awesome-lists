rule VirTool_Win32_SuspPowershellDownload_A_2147957143_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspPowershellDownload.A"
        threat_id = "2147957143"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspPowershellDownload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = " -nop -exec bypass " wide //weight: 1
        $x_1_3 = "IEX (" wide //weight: 1
        $x_1_4 = "Net.Webclient" wide //weight: 1
        $x_1_5 = ".downloadstring(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

