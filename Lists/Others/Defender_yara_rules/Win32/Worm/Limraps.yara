rule Worm_Win32_Limraps_A_2147617619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Limraps.A"
        threat_id = "2147617619"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Limraps"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {c7 45 f8 1a 00 00 00 59 fe 45 08 8d 45 08 50 ff 15 ?? ?? ?? ?? 83 f8 02 0f 85}  //weight: 4, accuracy: Low
        $x_4_2 = {8a 54 0d a8 41 88 50 ff 88 18 40 40 83 f9 28 7c ef}  //weight: 4, accuracy: High
        $x_4_3 = {8b 46 04 ff 36 40 50 8b 46 10 ff 76 08 40 ff 76 0c 50 8b 46 14 05 6c 07 00 00}  //weight: 4, accuracy: High
        $x_1_4 = "Message-ID: <%d%02d%02d%02d%02d%02d%d@mx.google.com>" ascii //weight: 1
        $x_1_5 = "[autorun]" ascii //weight: 1
        $x_1_6 = "tftp -i %s get %s" ascii //weight: 1
        $x_1_7 = "From: your friend." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

