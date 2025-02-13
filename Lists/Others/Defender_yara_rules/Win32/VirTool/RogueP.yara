rule VirTool_Win32_RogueP_A_2147758792_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/RogueP.A!MTB"
        threat_id = "2147758792"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "RogueP"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "localhost/pipe/%s[\\pipe\\epmapper]" ascii //weight: 1
        $x_1_2 = {48 8b d5 48 8d 0d 19 9f 01 00 e8 ?? ?? ?? ?? 45 33 c0 ba d2 04 00 00 41 8d 48 01 ff ?? ?? ?? ?? ?? 85 c0 74 13 48 8d 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_RogueP_B_2147758793_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/RogueP.B!MTB"
        threat_id = "2147758793"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "RogueP"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 16 48 8b 4d ?? ?? ?? ?? ?? ?? ?? 8b fb 48 8b ce 85 c0 b8 01 00 00 00 0f 45 f8 e8 ?? ?? ?? ?? 48 8b 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {85 ff 0f 84 3b 01 00 00 48 8b 4d 88 ff ?? ?? ?? ?? ?? 85 c0 0f 84 29 01 00 00 ff ?? ?? ?? ?? ?? 8b d0 48 8d ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

