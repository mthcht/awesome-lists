rule Trojan_Win32_Fakrano_A_2147726679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fakrano.A!bit"
        threat_id = "2147726679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakrano"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1QF12rwjKPee9cFHf1CFCwBnRu4x8kQD9M" wide //weight: 1
        $x_1_2 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\@.exe" wide //weight: 1
        $x_1_3 = "\\scsjsddcsdcjsjco" wide //weight: 1
        $x_1_4 = "cmd /c timeout 1 & del" wide //weight: 1
        $x_1_5 = "taskkill /f /im explorer.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

