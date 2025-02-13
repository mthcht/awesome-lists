rule TrojanDropper_Win32_Gemeindru_A_2147608693_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Gemeindru.gen!A"
        threat_id = "2147608693"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Gemeindru"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d e7 03 00 00 0f 80 ?? 06 00 00 50 ff 75 ?? 68 e8 03 00 00 e8 ?? ?? ff ff 53 e8 ?? ?? ff ff e8 ?? ?? 00 00 8b d0 8d 4d ?? e8 ?? ?? ff ff 50 68 ?? ?? ?? ?? e8 ?? ?? ff ff 8b d0 8d 4d ?? e8 ?? ?? ff ff 8d 4d ?? e8 ?? ?? ff ff c7 85 ?? ff ff ff ?? ?? ?? ?? c7 85 ?? ff ff ff 08 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

