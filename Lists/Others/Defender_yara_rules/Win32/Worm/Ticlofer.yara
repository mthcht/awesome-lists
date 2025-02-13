rule Worm_Win32_Ticlofer_A_2147629049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ticlofer.A"
        threat_id = "2147629049"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ticlofer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b3 62 8d 45 f4 8b d3 e8 ?? ?? ?? ?? 8d 45 f4 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 f4 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 f8 02 75 06 c6 45 ff 01 eb 06 43 80 fb 7b 75 ca}  //weight: 1, accuracy: Low
        $x_1_2 = {84 c0 74 21 bb 02 00 00 00 b8 08 00 00 00 e8 ?? ?? ?? ?? 8b 14 85 ?? ?? ?? ?? 8d 45 fc e8 ?? ?? ?? ?? 4b 75 e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

