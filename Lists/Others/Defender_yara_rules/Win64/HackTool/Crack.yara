rule HackTool_Win64_Crack_2147852498_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Crack!MTB"
        threat_id = "2147852498"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Crack"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetWindow" ascii //weight: 1
        $x_1_2 = "Enter password" ascii //weight: 1
        $x_1_3 = "CGP Co & m0nkrus" ascii //weight: 1
        $x_1_4 = "Acrobat Pro" ascii //weight: 1
        $x_1_5 = "crack.exe" ascii //weight: 1
        $n_100_6 = "Uninst.exe" ascii //weight: -100
        $n_100_7 = "Uninstall.exe" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

