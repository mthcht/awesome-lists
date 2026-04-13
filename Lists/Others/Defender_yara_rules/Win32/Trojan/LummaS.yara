rule Trojan_Win32_LummaS_B_2147965929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaS.B"
        threat_id = "2147965929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaS"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--processStart=pythonw.exe" wide //weight: 1
        $x_1_2 = "--process-start-args=LICENSE.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaS_A_2147966867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaS.A"
        threat_id = "2147966867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaS"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "--update=" wide //weight: 1
        $x_1_3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-255] 2e 00 70 00 61 00 67 00 65 00 73 00 2e 00 64 00 65 00 76 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

