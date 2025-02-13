rule Trojan_Win32_Portop_A_2147742009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Portop.A"
        threat_id = "2147742009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Portop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "it is holy shit" ascii //weight: 5
        $x_2_2 = "svhhost.exe" ascii //weight: 2
        $x_2_3 = "svhost.exe" ascii //weight: 2
        $x_1_4 = "cmd /c taskkill /f /im %s && taskkill /f /im %s" ascii //weight: 1
        $x_1_5 = "Mux: %s is existing,quit it!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Portop_B_2147742066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Portop.B"
        threat_id = "2147742066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Portop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Global\\D0E858DF-985E-4907-B7FB-8D732C3FC3B8}" ascii //weight: 2
        $x_2_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_2_3 = "cmd /c start /b  /ru system /sc @echo off" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

