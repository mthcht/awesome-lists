rule TrojanDropper_Win32_Bodsuds_A_2147623519_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bodsuds.A"
        threat_id = "2147623519"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bodsuds"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7c 24 14 00 75 37 68 ?? ?? ?? ?? 57 ff d6 59 59 85 c0 75 0e 57 8d 44 24 1c 50 ff 15 ?? ?? ?? ?? eb 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 00 00 c0 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 89 85 ?? ?? ff ff c7 85 ?? ?? ff ff 4d 5a 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

