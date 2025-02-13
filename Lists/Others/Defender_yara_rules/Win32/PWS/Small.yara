rule PWS_Win32_Small_BA_2147657113_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Small.BA"
        threat_id = "2147657113"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 00 6f 00 73 00 68 00 69 00 62 00 61 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 [0-160] 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = "login=" wide //weight: 1
        $x_1_3 = "&passwd=" wide //weight: 1
        $x_1_4 = "\\webc.exe" wide //weight: 1
        $x_1_5 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-208] 2e 00 6c 00 6f 00 67 00 69 00 6e 00 66 00 6f 00 72 00 2e 00 75 00 73 00 2f 00 [0-32] 2f 00 73 00 61 00 76 00 65 00 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

