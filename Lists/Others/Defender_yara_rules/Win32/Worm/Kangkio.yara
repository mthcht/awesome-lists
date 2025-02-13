rule Worm_Win32_Kangkio_A_2147610934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kangkio.A"
        threat_id = "2147610934"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kangkio"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d0 c2 bd a8 ce c4 bc fe bc d0 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {2a 2e 2a 00 25 73 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73}  //weight: 1, accuracy: High
        $x_1_3 = "http://%77%77%77%2E%" ascii //weight: 1
        $x_1_4 = "\\KillJpg.exe" ascii //weight: 1
        $x_1_5 = {c8 ce ce f1 b9 dc c0 ed 00}  //weight: 1, accuracy: High
        $x_1_6 = {ce c4 bc fe bc d0 d1 a1 cf ee 00}  //weight: 1, accuracy: High
        $x_3_7 = {6a 00 6a 00 68 00 08 00 00 52 ff d3 8b 44 24 10 8b 4f 04 50 6a 10 6a 00 51 ff d3 8d 4c 24 10 c7 84 24 ?? ?? ?? 00 ff ff ff ff e8 ?? ?? ?? 00 8b 96 ?? ?? ?? 00 8b 46 20 8b 3d ?? ?? 40 00 52 6a 01 68 80 00 00 00}  //weight: 3, accuracy: Low
        $x_2_8 = {8b 01 83 f8 ff 74 1f 8b ac 24 ?? ?? 00 00 8b 35 ?? ?? 40 00 6a 00 6a 00 6a 10 55 ff d6 6a 00 6a 00 6a 02 55 ff d6 8d 4c 24 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

