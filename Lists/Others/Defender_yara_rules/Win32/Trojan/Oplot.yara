rule Trojan_Win32_Oplot_B_2147735863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oplot.B"
        threat_id = "2147735863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oplot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\App\\AppXbf13d4ea2945444d8b13e2121cb6b663\\Application" wide //weight: 1
        $x_1_2 = "SOFTWARE\\App\\AppXbf13d4ea2945444d8b13e2121cb6b663\\DefaultIcon" wide //weight: 1
        $x_1_3 = "SOFTWARE\\App\\AppX70162486c7554f7f80f481985d67586d\\Application" wide //weight: 1
        $x_1_4 = "SOFTWARE\\App\\AppX70162486c7554f7f80f481985d67586d\\DefaultIcon" wide //weight: 1
        $x_1_5 = "SOFTWARE\\App\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\Application" wide //weight: 1
        $x_1_6 = "SOFTWARE\\App\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\DefaultIcon" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

