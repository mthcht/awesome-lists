rule VirTool_Win32_Procdopplegang_A_2147911228_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Procdopplegang.A"
        threat_id = "2147911228"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Procdopplegang"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 ec 6a 04 68 00 30 00 00 8b b0 ?? 02 00 00 03 30 56 50 ff 75 f0 ff ?? ?? ?? ?? ?? 8b 45 ec 6a 00 56 8b 35 00 30 40 00 50 50 ff 75 f0 ff ?? 85 c0 ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {83 ec 3c a1 ?? ?? ?? ?? 33 c5 89 45 fc 53 56 57 6a 00 6a 00 6a 00 8b da 89 4d d0 53 6a 04 ff ?? ?? ?? ?? ?? 50 6a 00 68 ff ff 1f 00 ?? ?? ?? 50 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 6a 00 6a 00 57 6a 00 6a 00 ff 75 f0 ff ?? ?? ?? ?? ?? 8b f8 85 ff ?? ?? ff ?? ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

