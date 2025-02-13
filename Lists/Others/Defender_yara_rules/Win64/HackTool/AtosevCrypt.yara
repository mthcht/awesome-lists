rule HackTool_Win64_AtosevCrypt_SI_2147773414_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/AtosevCrypt.SI!MTB"
        threat_id = "2147773414"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "AtosevCrypt"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 4d 8d 40 01 8b c6 ff c6 f7 f5 42 0f b6 04 3a 43 32 44 01 ff 41 88 40 ff 3b f3 72}  //weight: 10, accuracy: High
        $x_2_2 = {48 8b d0 48 8b cf ff 15 ?? ?? 00 00 48 85 c0 74 ?? 48 8b c8 ff 15 ?? ?? 00 00 48 8b d5 48 8b cf 4c 8b f0 ff 15 ?? ?? 00 00 8b e8 4d 85 f6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

