rule Backdoor_Win32_Beasty_2147499987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Beasty"
        threat_id = "2147499987"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Beasty"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "set cdaudio door open" ascii //weight: 1
        $x_1_2 = "************ Boot:[" ascii //weight: 1
        $x_1_3 = "Chat session started by " ascii //weight: 1
        $x_1_4 = {6d 73 6c 00 47 65 74 53 63 72 65 65 6e 00 00 00 47 65 74 57 65 62 43 61 6d}  //weight: 1, accuracy: High
        $x_1_5 = {47 65 74 5f 43 61 6d 00 47 5f 53}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

