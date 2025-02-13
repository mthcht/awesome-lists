rule VirTool_Win32_PeCloak_2147752139_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/PeCloak!MTB"
        threat_id = "2147752139"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PeCloak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 f6 31 ff [0-48] 3d ?? ?? ?? ?? 75 [0-48] 3d ?? ?? ?? ?? 75 [0-48] 3d ?? ?? ?? ?? 75 [0-48] b8 [0-16] 80 30 [0-48] 80 28 [0-48] 80 00 [0-48] 40 3d ?? ?? ?? ?? 7e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

