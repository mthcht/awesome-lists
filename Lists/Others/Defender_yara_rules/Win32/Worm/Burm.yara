rule Worm_Win32_Burm_2147608026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Burm"
        threat_id = "2147608026"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Burm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 00 2a 00 5c 00 41 00 43 00 3a 00 5c 00 4d 00 5c 00 4d 00 5c 00 42 00 75 00 73 00 68 00 20 00 76 00 [0-32] 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = "http://www.notijuegoss.com" wide //weight: 1
        $x_1_3 = {89 7d e0 89 7d d0 6a 01 ff 15 ?? ?? ?? ?? b8 ?? ?? ?? ?? b9 08 00 00 00 83 ec 10 8b d4 89 0a 8b 4d d4 89 4a 04 89 42 08 8b 45 dc 89 42 0c 6a 01 6a 68 8b 0e 56 ff 91 ?? ?? ?? ?? 50 8d 55 e0 52 8b 1d ?? ?? ?? ?? ff d3 50 ff 15 ?? ?? ?? ?? 83 c4 1c 8d 4d e0 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Burm_2147608026_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Burm"
        threat_id = "2147608026"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Burm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 00 2a 00 5c 00 41 00 43 00 3a 00 5c 00 4d 00 5c 00 4d 00 5c 00 42 00 75 00 73 00 68 00 20 00 76 00 [0-32] 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Task Manager" wide //weight: 1
        $x_1_3 = "Administrador de tareas" wide //weight: 1
        $x_1_4 = {c7 45 fc 01 00 00 00 c7 45 fc 02 00 00 00 6a ff ff 15 ?? ?? ?? ?? c7 45 fc 03 00 00 00 ba [0-4] 8d 4d dc ff 15 ?? ?? ?? ?? 8d 55 dc 52 e8 ?? ?? ?? ?? 8d 4d dc ff 15 ?? ?? ?? ?? c7 45 fc 04 00 00 00 ba ?? ?? ?? ?? 8d 4d dc ff 15 ?? ?? ?? ?? 8d 45 dc 50 e8 ?? ?? ?? ?? 8d 4d dc ff 15 ?? ?? ?? ?? c7 45 f0 00 00 00 00 68 ?? ?? ?? ?? eb 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Burm_2147608026_2
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Burm"
        threat_id = "2147608026"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Burm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 00 2a 00 5c 00 41 00 43 00 3a 00 5c 00 4d 00 5c 00 4d 00 5c 00 42 00 75 00 73 00 68 00 20 00 76 00 [0-32] 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = "it watches this animation of bush :P" wide //weight: 1
        $x_1_3 = "mira esta animacion de bush :P" wide //weight: 1
        $x_1_4 = {c7 45 fc 25 00 00 00 c7 45 9c 04 00 02 80 c7 45 94 0a 00 00 00 8d 4d 94 51 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8d 4d 94 ff 15 ?? ?? ?? ?? c7 45 fc 26 00 00 00 ff 15 ?? ?? ?? ?? c7 45 fc 27 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b d0 8d 4d b0 ff 15 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 89 45 9c c7 45 94 08 00 00 00 8d 55 94 8d 4d b4 ff 15 ?? ?? ?? ?? 8d 4d b0 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

