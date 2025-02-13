rule Trojan_Win32_Sholeat_A_2147627009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sholeat.A"
        threat_id = "2147627009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sholeat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 10, accuracy: High
        $x_10_2 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 [0-2] 48 00 6f 00 73 00 74 00 73 00 2e 00 65 00 78 00 65 00 [0-13] 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 [0-4] 48 00 6f 00 73 00 74 00 73 00}  //weight: 10, accuracy: Low
        $x_1_3 = "@mssrv245.dat" wide //weight: 1
        $x_1_4 = "%sfile%04u%s" wide //weight: 1
        $x_1_5 = "http://googleads." wide //weight: 1
        $x_1_6 = "Global\\{51E1C7A3-0033-4682-B97F-501905E717B7" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

