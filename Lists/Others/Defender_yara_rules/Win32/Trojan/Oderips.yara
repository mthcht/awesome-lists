rule Trojan_Win32_Oderips_2147616170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oderips"
        threat_id = "2147616170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oderips"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "up1.sidepro.co.kr" ascii //weight: 10
        $x_10_2 = "%02x-%02x-%02x-%02x-%02x-%02x" ascii //weight: 10
        $x_3_3 = {73 65 74 75 70 36 30 00 65 7a 69 6e 69 74 2e 65 78 65}  //weight: 3, accuracy: High
        $x_3_4 = "Microspro WebSoftware " ascii //weight: 3
        $x_2_5 = "install2.mdvirus.com" ascii //weight: 2
        $x_2_6 = {00 4d 44 56 69 72 75 73 44 42 00}  //weight: 2, accuracy: High
        $x_1_7 = "spoolsp.exe" ascii //weight: 1
        $x_1_8 = "svchosp.exe" ascii //weight: 1
        $x_1_9 = "logonsp.exe" ascii //weight: 1
        $x_1_10 = "explorsp.exe" ascii //weight: 1
        $x_1_11 = "notedsp.exe" ascii //weight: 1
        $x_1_12 = "systemsp.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

