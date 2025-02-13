rule Trojan_Win32_Sudesroc_A_2147705963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sudesroc.A"
        threat_id = "2147705963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sudesroc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "prive-budokay.no-ip.org" wide //weight: 2
        $x_1_2 = "p://45.55.250.175/ping/" wide //weight: 1
        $x_1_3 = "200.98.71.203" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

