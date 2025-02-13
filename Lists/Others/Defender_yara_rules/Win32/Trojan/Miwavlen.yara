rule Trojan_Win32_Miwavlen_B_2147649523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miwavlen.B"
        threat_id = "2147649523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miwavlen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Dados de aplicativos\\Scpad\\*.*" wide //weight: 1
        $x_1_2 = "\\GbPlugin\\GbpSv.exe" wide //weight: 1
        $x_1_3 = "\\Gbp.log" wide //weight: 1
        $x_1_4 = "a.exe" wide //weight: 1
        $x_1_5 = "h2.dll" wide //weight: 1
        $x_1_6 = "fg.bin" wide //weight: 1
        $x_1_7 = "resultadoa" wide //weight: 1
        $x_1_8 = "resultadoe" wide //weight: 1
        $x_1_9 = "resultadoi" wide //weight: 1
        $x_1_10 = "CONFLICT.1\\*.*" wide //weight: 1
        $x_1_11 = "\\scplib.dll" wide //weight: 1
        $x_1_12 = "\\scpmib.dll" wide //weight: 1
        $x_1_13 = "\\sshib.dll" wide //weight: 1
        $x_1_14 = "\\Logof.dll" wide //weight: 1
        $x_1_15 = "\\Downloaded Program Files" wide //weight: 1
        $x_1_16 = "VB OpenUrl" wide //weight: 1
        $x_1_17 = {5c 00 52 00 75 00 6e 00 00 00 02 00 00 00 5c 00 00 00 08 00 00 00 2e 00 65 00 78 00 65 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

