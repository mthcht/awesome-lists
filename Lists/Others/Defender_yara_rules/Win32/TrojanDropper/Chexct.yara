rule TrojanDropper_Win32_Chexct_A_2147658696_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Chexct.A"
        threat_id = "2147658696"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Chexct"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 48 28 8b 90 0c 01 00 00 2b 88 04 01 00 00 8d 04 32 03 ca 8b d0 2b d1 89 84 24 ?? ?? 00 00 83 c2 ?? 89 54 24 ?? 8b d1 2b d0 8a 04 39}  //weight: 1, accuracy: Low
        $x_1_2 = {85 c6 44 24 ?? c0 c6 44 24 ?? 75 c6 44 24 ?? ?? c6 44 24 ?? 6a c6 44 24 ?? 0a c6 44 24 ?? 04 c6 44 24 ?? ?? c6 44 24 ?? 81 04 00 c6 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

