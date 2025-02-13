rule Trojan_Win32_Tixinbir_A_2147779068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tixinbir.A"
        threat_id = "2147779068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tixinbir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\windows\\system32\\rundll32.exe" wide //weight: 1
        $x_1_2 = "\\appdata\\" wide //weight: 1
        $x_1_3 = "update" wide //weight: 1
        $x_1_4 = "/i:" wide //weight: 1
        $x_1_5 = ".dat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

