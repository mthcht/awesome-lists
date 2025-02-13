rule Trojan_Win32_Bafi_M_2147660267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bafi.M"
        threat_id = "2147660267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "200"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {40 25 0f 00 00 80 79 05 48 83 c8 f0 40 88 45 ff 8a 01 8a d0 32 d3 88 14 0e 41 ff 4d f4}  //weight: 100, accuracy: High
        $x_80_2 = {73 00 69 00 67 00 6e 00 20 00 69 00 6e 00 00 00 3c 00 43 00 4c 00 45 00 41 00 52 00 3e 00 00 00 73 00 68 00 6f 00 77 00 70 00 6f 00 70 00 75 00 70 00 00 00 63 00 6c 00 65 00 61 00 72 00}  //weight: 80, accuracy: High
        $x_50_3 = "Classes\\linkrd.AIEbho\\CLSID" wide //weight: 50
        $x_20_4 = "sAdobe_PDF_Reader_Hlp_Mtx" wide //weight: 20
        $x_10_5 = "DD31495E-290C-41CF-8C66-7415383F82DE" wide //weight: 10
        $x_10_6 = "F535DD2D-9339-48ED-A378-61084B1049AB" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_80_*) and 2 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_80_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_80_*) and 1 of ($x_50_*))) or
            (all of ($x*))
        )
}

