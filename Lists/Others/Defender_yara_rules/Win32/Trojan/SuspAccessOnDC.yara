rule Trojan_Win32_SuspAccessOnDC_A_2147960564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspAccessOnDC.A!hva"
        threat_id = "2147960564"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspAccessOnDC"
        severity = "Critical"
        info = "hva: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 00 5c 00 3f 00 5c 00 67 00 6c 00 6f 00 62 00 61 00 6c 00 72 00 6f 00 6f 00 74 00 5c 00 64 00 65 00 76 00 69 00 63 00 65 00 5c 00 68 00 61 00 72 00 64 00 64 00 69 00 73 00 6b 00 76 00 6f 00 6c 00 75 00 6d 00 65 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 [0-4] 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 6e 00 74 00 64 00 73 00 5c 00 6e 00 74 00 64 00 73 00 2e 00 64 00 69 00 74 00}  //weight: 10, accuracy: Low
        $x_10_2 = {5c 00 5c 00 3f 00 5c 00 67 00 6c 00 6f 00 62 00 61 00 6c 00 72 00 6f 00 6f 00 74 00 5c 00 64 00 65 00 76 00 69 00 63 00 65 00 5c 00 68 00 61 00 72 00 64 00 64 00 69 00 73 00 6b 00 76 00 6f 00 6c 00 75 00 6d 00 65 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 [0-4] 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6f 00 6e 00 66 00 69 00 67 00 5c 00}  //weight: 10, accuracy: Low
        $n_100_3 = "Veritas" wide //weight: -100
        $n_100_4 = "Symantec" wide //weight: -100
        $n_100_5 = "\\system32\\config\\systemprofile" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

