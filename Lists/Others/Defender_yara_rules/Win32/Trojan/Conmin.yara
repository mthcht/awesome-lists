rule Trojan_Win32_Conmin_A_2147664273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Conmin.A"
        threat_id = "2147664273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Conmin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 02 21 00 00 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 55 ?? 81 e2 ff 00 00 00 83 fa 01 75 18 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 8d 95 ?? ?? ff ff 52 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 6a 07 8d 8d ?? ?? ff ff 51 ff 15 ?? ?? ?? ?? b0 01}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 6a 00 68 ?? ?? ?? ?? 8b 55 08 52 6a 00 ff 55 f8 68 02 21 00 00 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 55 f4 83 c2 01 89 55 f4 81 7d f4 ?? 00 00 00 73 1b 8b 45 fc 03 45 f8 8b 4d f4 8a 10 32 91 ?? ?? ?? ?? 8b 45 fc 03 45 f8 88 10 eb}  //weight: 1, accuracy: Low
        $x_2_5 = " -t 6 -o http://mining.eligius.st:8337 -u" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

