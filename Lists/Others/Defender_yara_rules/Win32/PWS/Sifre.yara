rule PWS_Win32_Sifre_A_2147688933_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sifre.A"
        threat_id = "2147688933"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sifre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "HAKOPS LOGGER v" wide //weight: 15
        $x_5_2 = "EkranGoruntusu.jpg" wide //weight: 5
        $x_2_3 = "CDO.Message" wide //weight: 2
        $x_1_4 = "netsh firewall set opmode disable" wide //weight: 1
        $x_1_5 = "net stop security center" wide //weight: 1
        $x_1_6 = "net stop WinDefend" wide //weight: 1
        $x_5_7 = "\\Microsoft Archives\\SS.jpg" wide //weight: 5
        $x_2_8 = "\\FileZilla\\recentservers.xml" wide //weight: 2
        $x_3_9 = "\\Sifreler.txt" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

