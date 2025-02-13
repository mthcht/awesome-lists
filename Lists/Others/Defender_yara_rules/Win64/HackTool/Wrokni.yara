rule HackTool_Win64_Wrokni_C_2147735108_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Wrokni.C"
        threat_id = "2147735108"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Wrokni"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 5f 4c 45 5f}  //weight: 1, accuracy: High
        $x_1_2 = "VideoDriver" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

