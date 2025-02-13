rule Trojan_Win32_Statinfru_A_2147717740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Statinfru.A!bit"
        threat_id = "2147717740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Statinfru"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "speedboost2.exe" wide //weight: 1
        $x_2_2 = "http://staticinfo.ru" wide //weight: 2
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "variety speed" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

