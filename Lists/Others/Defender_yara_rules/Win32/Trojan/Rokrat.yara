rule Trojan_Win32_Rokrat_A_2147913232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rokrat.A"
        threat_id = "2147913232"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rokrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--wwjaughalvncjwiajs--" ascii //weight: 1
        $x_1_2 = "https://api.pcloud.com" ascii //weight: 1
        $x_1_3 = "Content-Type: voice/mp3" ascii //weight: 1
        $x_1_4 = "dir /A /S %s >>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

