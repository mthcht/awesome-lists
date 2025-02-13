rule VirTool_Win32_HackerHouse_A_2147755612_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/HackerHouse.A!MTB"
        threat_id = "2147755612"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "HackerHouse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {10 6a 40 68 00 10 00 00 68 ?? ?? ?? ?? [0-2] 50 ff 15 ?? ?? ?? 10 8b f8 b9 ?? ?? ?? ?? be ?? ?? ?? 10 f3 a5 66 a5 a4 ff d0}  //weight: 2, accuracy: Low
        $x_2_2 = {55 8b ec 83 6d 0c 01 75 20 6a 00 6a 00 6a 00 68 ?? ?? ?? 10 6a 00 6a 00 ff 15 ?? ?? ?? 10 85 c0 74 07 50 ff 15}  //weight: 2, accuracy: Low
        $x_2_3 = "payload.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

