rule HackTool_Win32_Loader_2147730821_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Loader!MTB"
        threat_id = "2147730821"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Loader"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "LightBurn.exe" ascii //weight: 2
        $x_1_2 = "JohnDoe" ascii //weight: 1
        $x_1_3 = "Nothing to patch! exiting.." ascii //weight: 1
        $n_100_4 = "Uninst.exe" ascii //weight: -100
        $n_100_5 = "Uninstall.exe" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

