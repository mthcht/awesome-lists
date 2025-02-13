rule HackTool_Win32_InstallWimTweak_A_2147829955_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/InstallWimTweak.A"
        threat_id = "2147829955"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "InstallWimTweak"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "install_wim_tweak.pdb" ascii //weight: 1
        $x_1_2 = "install_wim_tweak.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

