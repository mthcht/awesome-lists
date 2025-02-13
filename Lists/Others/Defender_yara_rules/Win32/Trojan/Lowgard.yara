rule Trojan_Win32_Lowgard_A_2147681617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lowgard.A"
        threat_id = "2147681617"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lowgard"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "OsraBcLuPG" wide //weight: 1
        $x_1_2 = {8d 4d c0 ba ?? ?? 52 00 8b 45 fc e8 ?? ?? ?? ?? 8b 45 c0 e8 ?? ?? ?? ?? 50 6a 00 6a 00 e8 ?? ?? ?? ?? 6a 00 8d 4d b8 ba ?? ?? 52 00 8b 45 fc e8 ?? ?? ?? ?? ff 75 b8 68 ?? ?? 52 00 68 ?? ?? 52 00 8d 45 bc ba 03 00 00 00 e8 ?? ?? ?? ?? 8b 4d bc ba ?? ?? 52 00 8b 45 fc e8 ?? ?? ?? ?? 8d 4d b0 ba ?? ?? 52 00 8b 45 fc e8 ?? ?? ?? ?? ff 75 b0 68 ?? ?? 52 00 68 ?? ?? 52 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

