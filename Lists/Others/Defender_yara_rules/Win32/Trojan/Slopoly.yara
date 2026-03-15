rule Trojan_Win32_Slopoly_B_2147964822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Slopoly.B"
        threat_id = "2147964822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Slopoly"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bot_ip:" ascii //weight: 1
        $x_1_2 = "elevated:" ascii //weight: 1
        $x_1_3 = "session_id:" ascii //weight: 1
        $x_1_4 = "user:" ascii //weight: 1
        $x_1_5 = "bot:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

