rule VirTool_Win32_RemcInj_2147742420_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/RemcInj!MTB"
        threat_id = "2147742420"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcInj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 fb 00 7f 70 00 83 eb 02 10 00 83 eb 02 [0-16] ff 34 1f [0-21] 8f 04 18 [0-64] 31 34 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

