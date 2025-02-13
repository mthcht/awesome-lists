rule Worm_Win32_Pizbot_2147602676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pizbot"
        threat_id = "2147602676"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pizbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 33 45 d0 0f bf d0 52 ff 15 ?? ?? ?? ?? 8b d0 8d 4d c8 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b d0 8d 4d d4 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {66 33 45 d0 0f bf c0 50 e8 ?? ?? ?? ?? 8b d0 8d 4d c8 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b d0 8d 4d d4 e8}  //weight: 10, accuracy: Low
        $x_5_3 = {c7 45 fc 04 00 00 00 6a 00 6a 00 6a 10 8b 45 dc 50 e8 ?? ?? ff ff ff 15 ?? ?? ?? ?? c7 45 f0 00 00 00 00 68 ?? ?? ?? ?? eb 28}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

