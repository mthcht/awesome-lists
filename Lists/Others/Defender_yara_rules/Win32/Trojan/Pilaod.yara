rule Trojan_Win32_Pilaod_A_2147620380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pilaod.A"
        threat_id = "2147620380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pilaod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://www.fgetchr.cn:81/G/tj/1/1.asp?mac=" wide //weight: 10
        $x_10_2 = {5c 00 51 00 51 00 20 00 2e 00 6c 00 6e 00 6b 00 00 00 00 00 1e 00 00 00 5c 00 63 00 6f 00 6d 00 5c 00 61 00 76 00 69 00 72 00 65 00 76 00 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: High
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

