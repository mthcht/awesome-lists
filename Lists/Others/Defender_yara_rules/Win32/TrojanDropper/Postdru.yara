rule TrojanDropper_Win32_Postdru_A_2147608624_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Postdru.gen!A"
        threat_id = "2147608624"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Postdru"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 00 38 00 00 2b f3 56 8d 45 f4 b9 01 00 00 00 8b 15 ?? ?? ?? ?? e8 ?? ?? ff ff 83 c4 04 8b d3 8d 85 ?? ?? ff ff e8 ?? ?? ff ff e8 ?? ?? ff ff a1 ?? ?? ?? ?? c6 00 02 8b 55 fc 8d 85 ?? ?? ff ff e8 ?? ?? ff ff ba 01 00 00 00 8d 85 ?? ?? ff ff e8 ?? ?? ff ff e8 ?? ?? ff ff 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

