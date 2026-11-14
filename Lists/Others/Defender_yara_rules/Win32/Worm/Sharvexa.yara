rule Worm_Win32_Sharvexa_A_2147982150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Sharvexa.A"
        threat_id = "2147982150"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Sharvexa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 08 c7 85 80 fd ff ff 00 01 00 00 c7 44 24 04 ?? ?? ?? ?? 8d 85 a8 fe ff ff 89 04 24 e8 ?? ?? ?? ?? c7 44 24 04 ?? ?? ?? ?? 8d 85 88 fe ff ff 89 04 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 85 84 fd ff ff 89 44 24 10 c7 44 24 0c 01 00 00 00 c7 44 24 08 00 00 00 00 8d 85 a8 fe ff ff 89 44 24 04 c7 04 24 01 00 00 80 e8 ?? ?? ?? ?? 83 ec 14 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

