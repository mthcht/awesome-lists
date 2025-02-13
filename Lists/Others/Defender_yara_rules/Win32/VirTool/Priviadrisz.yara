rule VirTool_Win32_Priviadrisz_A_2147847414_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Priviadrisz.A!MTB"
        threat_id = "2147847414"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Priviadrisz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 04 01 00 00 8d ?? ?? ?? 50 6a 01 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8d}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 6a 02 6a 00 6a 00 ff ?? ff 74 24 18 6a 40 ff 15 ?? ?? ?? ?? 8b f8 8d}  //weight: 1, accuracy: Low
        $x_1_3 = {56 57 50 68 04 cb 41 00 53 ff 15 ?? ?? ?? ?? 83 c4 14 89 5c 24 30 53 68 2c cb 41 00 e8 ?? ?? ?? ?? 83 c4 08 8d ?? ?? ?? 68 14 80 00 00 50 6a 02 6a 00 ff 15 ?? ?? ?? ?? 8b}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 74 24 20 ff 74 24 28 6a 00 ff 15 ?? ?? ?? ?? 50 68 78 cb 41 00 e8 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

