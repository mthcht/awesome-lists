rule Worm_Win32_Mimail_YBG_2147969110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mimail.YBG!MTB"
        threat_id = "2147969110"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 01 05 00 9f 79 8d 47 00 00 00 00 00 00 00 00 e0 00 0e 01 0b 01 02 37 00 12 00 00 00 66 00 00 00 04 00 00 00 b0 00}  //weight: 1, accuracy: High
        $x_1_2 = {2e 69 65 6f 6f 00 00 00 00 10 00 00 00 b0 00 00 00 02 00 00 00 7e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

