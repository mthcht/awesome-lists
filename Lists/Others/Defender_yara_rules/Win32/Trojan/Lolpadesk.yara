rule Trojan_Win32_Lolpadesk_A_2147839192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lolpadesk.A!MTB"
        threat_id = "2147839192"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolpadesk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_2_2 = "LOLPA4DESK" ascii //weight: 2
        $x_1_3 = "EnumDesktopWindows" ascii //weight: 1
        $x_1_4 = "getaddrinfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

