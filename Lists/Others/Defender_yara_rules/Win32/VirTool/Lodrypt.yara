rule VirTool_Win32_Lodrypt_A_2147610111_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Lodrypt.A!dr"
        threat_id = "2147610111"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Lodrypt"
        severity = "Critical"
        info = "dr: dropper component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ff eb 1b ?? ?? ?? 32 c9 b8 ?? ?? ?? ?? fe c1 30 08 40 3d ?? ?? ?? ?? 7e f6 e9 ?? ?? 00 00 bb ?? ?? ?? ?? 66 b8 99 99 57 ff d3}  //weight: 1, accuracy: Low
        $x_1_2 = {ff ff 6a 0a 68 ?? ?? ?? ?? e8 ?? ?? ff ff 8d 55 e0 33 c0 e8 ?? ?? ff ff 8b 45 e0 8d 55 e4 e8 ?? ?? ff ff 8d 45 e4 ba ?? ?? ?? ?? e8 ?? ?? ff ff 8b 45 e4 e8 ?? ?? ff ff 33 c0 5a 59 59 64 89 10}  //weight: 1, accuracy: Low
        $x_1_3 = {52 54 5f 52 43 44 41 54 41 00 00 00 43 4f 4e 54 45 4e 54 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

