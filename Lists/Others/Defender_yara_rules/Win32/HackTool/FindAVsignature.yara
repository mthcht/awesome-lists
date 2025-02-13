rule HackTool_Win32_FindAVsignature_A_2147684123_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/FindAVsignature.A"
        threat_id = "2147684123"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "FindAVsignature"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Find-AVSignature" ascii //weight: 10
        $n_5_2 = "https://dotnetcli.blob.core.windows.net/" wide //weight: -5
        $n_5_3 = "-TenantServicePassword" wide //weight: -5
        $n_5_4 = "Rapid7 Agent" wide //weight: -5
        $n_10_5 = "\\MSTICWefDetections\\Lib\\PowershellParser\\obj\\amd64\\PowershellParser.pdb" ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

