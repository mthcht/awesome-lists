rule Worm_Win32_Culler_R_2147597130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Culler.R"
        threat_id = "2147597130"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Culler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\SysArc.exe" ascii //weight: 1
        $x_1_2 = "mira esta animacion de bush :P" ascii //weight: 1
        $x_1_3 = "Mensage a todos" ascii //weight: 1
        $x_1_4 = "Directorios del sistema" ascii //weight: 1
        $x_1_5 = {c7 45 fc 0c 00 00 00 6a 01 8b 55 08 8b 02 8b 4d 08 51 ff 90 ?? 07 00 00 c7 45 fc 0d 00 00 00 c7 45 bc 04 00 02 80 c7 45 b4 0a 00 00 00 8d 55 b4 52 68 ?? ?? 40 00 ff 15 ?? 10 40 00 8d 4d b4 ff 15 ?? 10 40 00 c7 45 fc 0e 00 00 00 c7 45 bc 04 00 02 80 c7 45 b4 0a 00 00 00 8d 45 b4 50 68 ?? ?? 40 00 ff 15 ?? 10 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

