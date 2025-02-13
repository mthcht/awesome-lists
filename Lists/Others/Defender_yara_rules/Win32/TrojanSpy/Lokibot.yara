rule TrojanSpy_Win32_Lokibot_V_2147740978_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Lokibot.V!MTB"
        threat_id = "2147740978"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b3 02 33 ff [0-6] 8b c7 [0-5] 8a 90 ?? ?? ?? ?? 32 d3 [0-5] a1 ?? ?? ?? ?? 03 c7 [0-4] 8b f0 [0-6] 8b c6 e8 ?? ?? ?? ?? [0-5] 47 81 ff ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

