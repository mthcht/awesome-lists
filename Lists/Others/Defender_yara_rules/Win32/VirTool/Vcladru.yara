rule VirTool_Win32_Vcladru_A_2147609406_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vcladru.A!dr"
        threat_id = "2147609406"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vcladru"
        severity = "Critical"
        info = "dr: dropper component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 0a 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_2 = {6a 02 68 00 00 00 40 8d 85 ?? fe ff ff 8b d3 e8 ?? ?? ff ff 8b 8d}  //weight: 1, accuracy: Low
        $x_1_3 = {50 56 6a 00 e8 ?? fe ff ff 50 e8 ?? fe ff ff 50 57 e8 ?? fe ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 55 f4 e8 ?? ?? ff ff 8b 85 ?? fe ff ff e8 ?? ?? ff ff 50 68 ?? ?? ?? ?? 6a 00 e8 ?? fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

