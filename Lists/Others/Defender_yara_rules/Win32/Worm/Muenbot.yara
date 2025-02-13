rule Worm_Win32_Muenbot_A_2147616302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Muenbot.gen!A"
        threat_id = "2147616302"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Muenbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {b9 eb 05 00 00 8d 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 00 8b 45 f8 50 8d 85 ?? ?? ?? ?? 50 8b 43 20 50 e8 ?? ?? ?? ?? 6a 01 e8 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 ba}  //weight: 5, accuracy: Low
        $x_5_2 = {3d 37 0c 00 00 7f 2b 0f 84 ?? ?? 00 00 2d 8b 00 00 00 74 4d 2d 32 01 00 00 74 5a 2d 63 01 00 00 74 67 2d 99 07 00 00}  //weight: 5, accuracy: Low
        $x_5_3 = {ba 8b 00 00 00 8b 45 fc e8 ?? ?? ?? ?? 8b d8 e9 ?? ?? ?? ?? ba bd 01 00 00 8b 45 fc e8}  //weight: 5, accuracy: Low
        $x_1_4 = "[%os%]%rc%%rn%" ascii //weight: 1
        $x_1_5 = "DmPaSsWrOnG" ascii //weight: 1
        $x_1_6 = "echo get unnamed.exe >> bla.txt" ascii //weight: 1
        $x_1_7 = "VERSION -unnamed bot" ascii //weight: 1
        $x_1_8 = ":[iNFO] Trying to manually root" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

