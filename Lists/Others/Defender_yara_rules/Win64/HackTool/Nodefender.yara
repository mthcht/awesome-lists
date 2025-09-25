rule HackTool_Win64_Nodefender_HAB_2147953029_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Nodefender.HAB!MTB"
        threat_id = "2147953029"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Nodefender"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 00 73 00 76 00 63 00 20 00 2f 00 75 00 70 00 64 00 61 00 74 00 65 00 20 00 2f 00 7b 00 7d 00 20 00 2f 00 73 00 74 00 61 00 74 00 65 00 3a 00 7b 00 7d 00 20 00 2f 00 73 00 69 00 67 00 6e 00 61 00 74 00 75 00 72 00 65 00 73 00 3a 00 75 00 70 00 5f 00 74 00 6f 00 5f 00 64 00 61 00 74 00 65 00 00 00 61 00 76 00 5f 00 61 00 73 00 00 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 00 00 00 00 61 00 73 00 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

