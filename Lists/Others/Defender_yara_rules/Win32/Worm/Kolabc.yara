rule Worm_Win32_Kolabc_C_2147626655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kolabc.C"
        threat_id = "2147626655"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kolabc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LANMAN1.0" ascii //weight: 1
        $x_1_2 = "\\\\%s\\pipe\\srvsvc" ascii //weight: 1
        $x_1_3 = "[autorun]" ascii //weight: 1
        $x_1_4 = "\\Internet Account Manager\\Accounts" ascii //weight: 1
        $x_1_5 = "Average[%d kbit/s]" ascii //weight: 1
        $x_1_6 = "Total shares [%s: %d]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

