rule Trojan_Win32_Spiltderp_A_2147697176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spiltderp.A"
        threat_id = "2147697176"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spiltderp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del \"%s\"" wide //weight: 4
        $x_2_2 = "User-Agent: StartpageInstaller 2.6.1" wide //weight: 2
        $x_2_3 = "api/installer/SetInstallStatus?data=" wide //weight: 2
        $x_2_4 = {c6 84 24 34 08 00 00 64 c6 84 24 33 08 00 00 74 c6 84 24 32 08 00 00 4e ff 15}  //weight: 2, accuracy: High
        $x_1_5 = "%APPDATA%\\SPI\\" wide //weight: 1
        $x_1_6 = "SPI\\ff.ico" wide //weight: 1
        $x_1_7 = "amigo.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

