rule Worm_Win32_MSNWorm_2147596740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/MSNWorm"
        threat_id = "2147596740"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "MSNWorm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "PRIVMSG %s : wow: %s" ascii //weight: 3
        $x_1_2 = {68 02 20 00 00 ff 15}  //weight: 1, accuracy: High
        $x_2_3 = {6a 00 6a 01 6a 00 6a 11 ff}  //weight: 2, accuracy: High
        $x_1_4 = {6a 00 6a 00 6a 00 6a 0d ff}  //weight: 1, accuracy: High
        $x_1_5 = {2e 7a 69 70 00}  //weight: 1, accuracy: High
        $x_2_6 = {41 2d 9e 24 dd 44 64 4d 9b 6b d5 fd 76}  //weight: 2, accuracy: High
        $x_2_7 = {6a 00 6a 03 6a 2d 6a 11 ff}  //weight: 2, accuracy: High
        $x_1_8 = "SetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

