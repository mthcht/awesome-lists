rule Trojan_Win32_Secrar_A_2147657112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Secrar.A"
        threat_id = "2147657112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Secrar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 fc 83 7d 08 05 75 ?? 83 7d fc 00 75 ?? c7 45 f4 00 00 00 00 8b 4d 0c 89 4d f8 8b 55 f8 89 55 f4 8b 45 f4 8b 4d f4 03 08 89 4d f8 8b 55 f8 0f b7 42 38 50}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 f4 8b 02 8b 4d f8 03 01 8b 55 f4 89 02 8b 45 f4 89 45 f8 8b 4d f4 83 39 00 75}  //weight: 1, accuracy: High
        $x_1_3 = "svchst.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

