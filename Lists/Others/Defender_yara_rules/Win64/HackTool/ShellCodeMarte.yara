rule HackTool_Win64_ShellCodeMarte_ZM_2147897756_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/ShellCodeMarte.ZM!MTB"
        threat_id = "2147897756"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeMarte"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {49 63 ca 8a 04 19 41 88 04 1b 40 88 34 19 41 0f b6 04 1b 48 03 c6 0f b6 c0 8a 0c 18 42 32 0c 02 41 88 08 49 ff c0 49 83 e9 01 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

