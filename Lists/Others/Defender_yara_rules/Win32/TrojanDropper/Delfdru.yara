rule TrojanDropper_Win32_Delfdru_A_2147607970_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Delfdru.gen!A"
        threat_id = "2147607970"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfdru"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 01 72 07 74 18 48 74 28 eb 37 8d 85 00 ff ff ff 50 68 00 01 00 00 e8 ?? ?? ?? ff eb 24 68 00 01 00 00 8d 85 00 ff ff ff 50 e8 ?? ?? ?? ff eb 11 68 00 01 00 00 8d 85 00 ff ff ff 50 e8 ?? ?? ?? ff 83 fb 02 75 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

