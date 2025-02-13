rule Worm_Win32_Bainoc_B_2147636016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bainoc.B"
        threat_id = "2147636016"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bainoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 f8 04 62 e8 ?? ?? ?? ?? 88 45 f7 8d 45 d8 8a 55 f7 e8 ?? ?? ?? ?? 8d 45 d8 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 d8 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b d8 80 fb 02 74 09 80 fb 03 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = "Infect PenDriver:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

