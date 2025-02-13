rule Trojan_Win32_Piver_A_2147709808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Piver.A"
        threat_id = "2147709808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Piver"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 52 75 6e 00 53 63 6e 43 66 67 00}  //weight: 1, accuracy: High
        $x_1_2 = "Rundll32.exe \"%s\",RunUninstall %s" wide //weight: 1
        $x_1_3 = "mswd%03X.tmp" wide //weight: 1
        $x_1_4 = {41 43 44 43 42 42 31 00 41 43 44 43 42 42 32}  //weight: 1, accuracy: High
        $x_1_5 = {5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 00 00 00 00 25 00 73 00 73 00 65 00 63 00 25 00 30 00 38 00 78 00 2e 00 62 00 61 00 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {49 50 52 49 50 [0-8] 53 79 73 57 4f 57 36 34 [0-8] 73 79 73 74 65 6d 33 32 [0-10] 73 63 20 63 72 65 61 74 65 20 25 73 20 62 69 6e 50 61 74 68 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

