rule Trojan_Win32_Renimoren_A_2147808363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Renimoren.A"
        threat_id = "2147808363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Renimoren"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "42JKzDhbU76Wbf7JSDhomw6utwLr3N8tjZXLzLwvTcPuP5ZGZiJAHwnD7dNf2ZSAh52i9cUefq2nmLK3azKBffkBMX5b1LY" wide //weight: 100
        $x_1_2 = "powershell" wide //weight: 1
        $x_1_3 = "cmd.exe" wide //weight: 1
        $x_1_4 = "xmrig.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Renimoren_B_2147808364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Renimoren.B"
        threat_id = "2147808364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Renimoren"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "152"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_50_2 = "http://lurchmath.org/wordpress-temp/wp-content/plugins/" wide //weight: 50
        $x_50_3 = "/plugins/mine.bat" wide //weight: 50
        $x_1_4 = ".downloadfile(" wide //weight: 1
        $x_1_5 = ".downloadstring(" wide //weight: 1
        $x_1_6 = "GetTempFileName" wide //weight: 1
        $x_1_7 = "System.Net.WebClient" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*))) or
            (all of ($x*))
        )
}

