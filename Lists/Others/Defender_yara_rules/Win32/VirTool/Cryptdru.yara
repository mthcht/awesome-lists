rule VirTool_Win32_Cryptdru_2147608450_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Cryptdru.gen!dr"
        threat_id = "2147608450"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptdru"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dr: dropper component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 24 6a 01 6a 01 ff 15 ?? ?? ?? ?? 83 e8 63 0f 80 ?? 05 00 00 50 8b 55 dc 52 6a 64 ff 15 ?? ?? ?? ?? 6a 01 ff 15 ?? ?? ?? ?? c7 85 ?? ff ff ff ?? ?? ?? ?? c7 85 ?? ff ff ff 08 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

