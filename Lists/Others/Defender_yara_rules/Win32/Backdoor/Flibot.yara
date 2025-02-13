rule Backdoor_Win32_Flibot_2147601658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Flibot"
        threat_id = "2147601658"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Flibot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "PING" wide //weight: 1
        $x_1_2 = "PONG" wide //weight: 1
        $x_1_3 = "JOIN" wide //weight: 1
        $x_5_4 = "FLVP@JKI" wide //weight: 5
        $x_10_5 = {66 33 45 d0 0f bf d0 52 ff 15 ?? ?? ?? ?? 8b d0 8d 4d c8 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b d0 8d 4d d4 ff 15}  //weight: 10, accuracy: Low
        $x_10_6 = {66 33 45 d0 0f bf c0 50 e8 ?? ?? ?? ?? 8b d0 8d 4d c8 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b d0 8d 4d d4 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

