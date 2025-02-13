rule VirTool_Win32_AccessMe_A_2147745056_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AccessMe.A!MTB"
        threat_id = "2147745056"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AccessMe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff d0 89 45 ?? c7 04 24 e8 03 00 00 a1 ?? ?? ?? 00 ff d0 83 ec 04 a1 ?? ?? ?? 00 ff d0}  //weight: 2, accuracy: Low
        $x_2_2 = {8d 70 01 89 34 24 e8 ?? ?? 00 00 89 43 fc 8b 4f fc 89 74 24 08 89 4c 24 04 89 04 24 e8 ?? ?? 00 00 39 7d 94 75 ca}  //weight: 2, accuracy: Low
        $x_2_3 = "C:\\WINDOWS\\WindowsUpdate.log" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

