rule Worm_Win32_Secrar_A_2147657111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Secrar.A"
        threat_id = "2147657111"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Secrar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 04 8d 45 ?? 50 6a 1e 6a ff ff 55 fc 85 c0 75 04 b0 01 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 03 14 81 52 e8 ?? ?? ?? ?? 83 c4 04 3b 45 0c 75 0f 8b 45 ?? 8b 4d ?? 0f b7 14 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

