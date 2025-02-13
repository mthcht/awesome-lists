rule Trojan_Win32_SourLogger_A_2147773981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SourLogger.A!dha"
        threat_id = "2147773981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SourLogger"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "5tr5t4re6trrw" ascii //weight: 1
        $x_1_2 = "[CTRL]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

