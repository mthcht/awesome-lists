rule Trojan_Win32_Sparv_2147610057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sparv"
        threat_id = "2147610057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sparv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "InternetOpenUrlA" ascii //weight: 10
        $x_10_2 = "RegSetValueExA" ascii //weight: 10
        $x_10_3 = "GetStartupInfoA" ascii //weight: 10
        $x_10_4 = "system32\\wniapsrv.exe" ascii //weight: 10
        $x_1_5 = {77 6e 69 61 70 73 72 76 00 00 00 00 49 45 58 50 4c 4f 52 45 2e 45 58 45}  //weight: 1, accuracy: High
        $x_1_6 = "system32\\config\\wniapsrv.ini" ascii //weight: 1
        $x_1_7 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 00 6f 70 65 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

