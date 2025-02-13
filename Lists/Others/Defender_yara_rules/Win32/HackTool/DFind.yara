rule HackTool_Win32_DFind_2147639951_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DFind"
        threat_id = "2147639951"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DFind"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 f8 52 0f ?? ?? ?? 00 00 0f be ?? ?? ?? ff ff 83 f8 46}  //weight: 2, accuracy: Low
        $x_1_2 = {ff ff 28 7c 20 0f be ?? ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = "open:%d vnc:%d passwd:%d" ascii //weight: 1
        $x_1_4 = "GET /w00tw00t" ascii //weight: 1
        $x_1_5 = "CACACACACACACACACACACACACACACABP" ascii //weight: 1
        $x_1_6 = "\\\\%s\\ipc$" ascii //weight: 1
        $x_1_7 = "&netbiosname:%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

