rule VirTool_Win32_SuspPowershellObfusExec_A_2147957699_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspPowershellObfusExec.A"
        threat_id = "2147957699"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspPowershellObfusExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = " -c " wide //weight: 1
        $x_1_3 = "IO.CoMPrESsiON.dEFlateStREAM" wide //weight: 1
        $x_1_4 = "::fRombAsE64STRIng(" wide //weight: 1
        $x_1_5 = ".reADtoeNd(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

