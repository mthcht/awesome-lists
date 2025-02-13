rule TrojanDropper_Win32_Moudoor_A_2147652728_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Moudoor.A"
        threat_id = "2147652728"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Moudoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Elevation:Administrator!new:{3a" wide //weight: 1
        $x_1_2 = {eb 0f 8b 85 ?? ?? ff ff 83 c0 01 89 85 00 ff ff 8b 8d 00 ff ff 3b 8d ?? ?? ff ff 73 25 8b 95 ?? ?? ff ff 03 95 00 ff ff 0f be 02 33 85 00 ff ff 8b 8d ?? ?? ff ff 03 8d 00 ff ff 88 01 eb be 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

