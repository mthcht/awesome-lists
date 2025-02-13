rule Trojan_Win32_Sycogvis_A_2147651203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sycogvis.A"
        threat_id = "2147651203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sycogvis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b de 75 05 8d 75 f8 2b cb 6a 00 e8 ?? ?? ?? ?? 31 5d fc 8b ce d3 7d fc 8a 4d fc d3 25 08 29 02 10 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {83 fe 01 75 35 8b 45 08 89 45 fc 8b 4d fc 33 c1 89 55 fc 89 45 08 8b 45 08 89 5d fc 09 05 7c 29 02 10 57 89 7d fc 8d 85 ec fd ff ff 50 ff 75 20 ff 75 f8}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 08 89 45 fc 8a 4d fc d3 f8 89 7e 08 89 55 fc 66 c7 06 09 00 89 45 08 8b 45 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

