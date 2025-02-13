rule Trojan_Win32_Phoetel_ST_2147742935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phoetel.ST!MTB"
        threat_id = "2147742935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phoetel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Phoenix Keylogger - Screenshot" wide //weight: 1
        $x_1_2 = "Phoenix Keylogger - Clipboard" wide //weight: 1
        $x_1_3 = "Phoenix Keylogger - Logs" wide //weight: 1
        $x_1_4 = "keyscrambler" wide //weight: 1
        $x_1_5 = "Phoenix Keylogger - Passwords" wide //weight: 1
        $x_1_6 = "=SeaMonkey=" wide //weight: 1
        $x_1_7 = "Mozilla\\SeaMonkey\\Profiles" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

