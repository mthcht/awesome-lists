rule Trojan_Win32_KuZhan_17748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KuZhan"
        threat_id = "17748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KuZhan"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\Program Files\\bind_" ascii //weight: 2
        $x_3_2 = "\\SOFTWARE\\Microsoft\\Internet Explorer\\Extensions\\{1D901067-2529-4A9B-9B6B-7A1DB3A44CB5}" ascii //weight: 3
        $x_3_3 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\{D1BB7CF4-4463-4e91-88D7-ECC3CE0A13B7}" ascii //weight: 3
        $x_2_4 = "C:\\Program Files\\kuzhan\\kuzhan.dll" ascii //weight: 2
        $x_2_5 = "sss1.sss2.1" ascii //weight: 2
        $x_2_6 = "C:\\Program Files\\Common Files\\UPDATE2\\update.exe.1" ascii //weight: 2
        $x_2_7 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\IE-Bar" ascii //weight: 2
        $x_3_8 = "http://0.82211.net/" ascii //weight: 3
        $x_5_9 = ".82211.net/" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((3 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

