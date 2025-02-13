rule Worm_Win32_Flibot_A_2147605702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Flibot.gen!A"
        threat_id = "2147605702"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Flibot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 33 45 d0 0f bf d0 52 ff 15 ?? ?? ?? ?? 8b d0 8d 4d c8 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b d0 8d 4d d4 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {66 33 45 d0 0f bf c0 50 e8 ?? ?? ?? ?? 8b d0 8d 4d c8 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b d0 8d 4d d4 e8}  //weight: 10, accuracy: Low
        $x_10_3 = {6b 70 ff fb 12 e7 0b ?? 00 04 00 23 44 ff 2a 31 74 ff 32 04 00 48 ff 44 ff 35 4c ff 00 0c 6b 70 ff f3 ff 00 c6 1c ?? ?? 00 07 f4 01 70 70 ff 1e ?? ?? 00 0b 6b 70 ff f4 01 a9 70 70 ff 00 0a 04 72 ff 64 6c}  //weight: 10, accuracy: Low
        $x_1_4 = "MK004.Wz1" ascii //weight: 1
        $x_1_5 = "\\MSVBVM60.DLL\\3" ascii //weight: 1
        $x_1_6 = "GetLogicalDriveStrings" ascii //weight: 1
        $x_1_7 = "remoteport" wide //weight: 1
        $x_2_8 = "oq2*" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

