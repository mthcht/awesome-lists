rule Trojan_Win32_PythonCurlDropper_A_2147970690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PythonCurlDropper.A!AMTB"
        threat_id = "2147970690"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PythonCurlDropper"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "curl.exe -T" wide //weight: 1
        $x_1_2 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-27] 2e 00 6c 00 6f 00 67 00}  //weight: 1, accuracy: Low
        $x_1_3 = ".pyc -o" wide //weight: 1
        $x_2_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 3a 00 35 00 30 00 30 00 30 00}  //weight: 2, accuracy: Low
        $x_2_5 = {70 00 79 00 74 00 68 00 6f 00 6e 00 5c 00 [0-7] 2e 00 70 00 79 00 63 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

