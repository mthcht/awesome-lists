rule Trojan_Win32_Mudwat_A_2147727392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mudwat.A"
        threat_id = "2147727392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mudwat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta.exe" wide //weight: 1
        $x_1_2 = "vbscript:Close(Execute(\"" wide //weight: 1
        $x_1_3 = "powershell.exe -w 1 -exec Bypass" wide //weight: 1
        $x_1_4 = "iex([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String((get-content C:\\ProgramData\\" wide //weight: 1
        $x_1_5 = ".ini))));\"\",0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

