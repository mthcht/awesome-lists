rule HackTool_Linux_NetSpy_B_2147893576_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/NetSpy.B!MTB"
        threat_id = "2147893576"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "NetSpy"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "netspy/core/spy" ascii //weight: 1
        $x_1_2 = "poll.splicePipe" ascii //weight: 1
        $x_1_3 = {48 89 ce 48 8d 05 a9 e8 01 00 e8 a4 ba df ff 48 8d 05 fd e0 03 00 e8 b8 56 df ff 48 89 84 24 e8 00 00 00 48 c7 40 08 04 00 00 00 48 8b 54 24 30 48 89 50 10 83 3d 88 f2 28 00 00 75 0d 48 8b 8c 24 88 01 00 00 48 89 08 eb 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

