rule Trojan_Win32_RatDown_A_2147755523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RatDown.A!MTB"
        threat_id = "2147755523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RatDown"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f [0-37] 2f 52 61 74 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f [0-37] 2f 41 73 79 6e 63 43 6c 69 65 6e 74 2e 62 69 6e}  //weight: 1, accuracy: Low
        $x_1_3 = "Could not hide file:" ascii //weight: 1
        $x_1_4 = "Could not set file to system file:" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_7 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

