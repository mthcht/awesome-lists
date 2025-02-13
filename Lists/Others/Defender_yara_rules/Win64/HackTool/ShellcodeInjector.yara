rule HackTool_Win64_ShellcodeInjector_AY_2147890104_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/ShellcodeInjector.AY!MTB"
        threat_id = "2147890104"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInjector"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 14 99 48 ff c3 48 3b d8 72 ?? 48 8b 5c 24 ?? 48 8d 04 85 ?? ?? ?? ?? 49 3b c1 73 ?? 0f 1f 00 30 14 08 48 ff c0 49 3b c1 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

