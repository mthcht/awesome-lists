rule HackTool_Win64_Cymulion_SA_2147902871_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Cymulion.SA!MTB"
        threat_id = "2147902871"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Cymulion"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c2 48 8d 0c 2a 83 e0 ?? 48 ff c2 0f b6 84 18 ?? ?? ?? ?? 32 04 0e 88 01 49 3b d6 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

