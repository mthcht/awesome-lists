rule Trojan_Win32_Ridok_A_2147652951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ridok.A"
        threat_id = "2147652951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ridok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {67 62 6f 74 2e 70 68 70 3f 63 6f 75 6e 74 72 79 3d 00}  //weight: 5, accuracy: High
        $x_5_2 = "9dedal" ascii //weight: 5
        $x_1_3 = "accept-language: ru" ascii //weight: 1
        $x_1_4 = "yandex.ru" ascii //weight: 1
        $x_1_5 = "googlebot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

