rule HackTool_Win64_NoDefender_MBYK_2147914467_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/NoDefender.MBYK!MTB"
        threat_id = "2147914467"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "NoDefender"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 33 c4 48 89 84 24 ?? ?? ?? ?? 48 8b fa 48 63 f1 45 33 f6 33 d2 41 b8 98 01}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8d 15 f1 99 06 00 48 8d 8c 24 00 03 00 00 e8 ?? ?? ?? 00 48 8b d8}  //weight: 1, accuracy: Low
        $x_1_3 = "/runassvc /rpcserver /wsc_name" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

