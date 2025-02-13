rule Trojan_Win32_Bypass_D_2147722590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bypass.D!bit"
        threat_id = "2147722590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bypass"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "REG ADD HKCU\\Software\\Classes\\mscfile\\shell\\open\\command" wide //weight: 1
        $x_1_2 = "start C:\\Windows\\System32\\eventvwr.exe" wide //weight: 1
        $x_1_3 = "REG DELETE HKCU\\Software\\Classes\\mscfile\\shell\\open\\command" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

