rule Worm_Win32_Sfone_A_2147609829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Sfone.A"
        threat_id = "2147609829"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Sfone"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {85 c0 75 1f 8b 85 ?? ?? ff ff 50 6a 00 68 ff 0f 1f 00 ff 15 58 67 41 00 89 c6 6a 00 56 ff 15 ?? ?? 41 00 83 c3 01 8b 04 9d ?? ?? 41 00 85 c0 75 a8 8d 85 ?? ?? ff ff 50 57 e8 8a 0c 00 00 83 f8 01 0f 84 00 ff ff ff}  //weight: 4, accuracy: Low
        $x_1_2 = "mutex666" ascii //weight: 1
        $x_1_3 = "thisisapassword!" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "AVprotect9X" ascii //weight: 1
        $x_1_6 = "notes.txt.exe" ascii //weight: 1
        $x_1_7 = "readme.txt.exe" ascii //weight: 1
        $x_1_8 = "incoming" ascii //weight: 1
        $x_1_9 = "share" ascii //weight: 1
        $x_1_10 = "upskirt" ascii //weight: 1
        $x_1_11 = "annie" ascii //weight: 1
        $x_1_12 = "nipples" ascii //weight: 1
        $x_1_13 = "glans" ascii //weight: 1
        $x_1_14 = "vagina" ascii //weight: 1
        $x_1_15 = "IcmpSendEcho" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_1_*))) or
            ((1 of ($x_4_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

