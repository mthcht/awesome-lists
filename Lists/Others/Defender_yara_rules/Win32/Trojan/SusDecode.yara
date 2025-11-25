rule Trojan_Win32_SusDecode_A_2147958181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDecode.A"
        threat_id = "2147958181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDecode"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "System.Text.Encoding]::UTF8.GetBytes(" ascii //weight: 1
        $x_1_4 = "FromBase64String(" ascii //weight: 1
        $x_1_5 = "Unicode.GetString([System.Convert]" ascii //weight: 1
        $x_1_6 = "Out-File(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SusDecode_B_2147958183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDecode.B"
        threat_id = "2147958183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDecode"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "mkdir" ascii //weight: 1
        $x_1_3 = "kworking" ascii //weight: 1
        $x_1_4 = "cert.exe -decode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

