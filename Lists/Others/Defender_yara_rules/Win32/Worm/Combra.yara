rule Worm_Win32_Combra_F_2147595061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Combra.F"
        threat_id = "2147595061"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Combra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 5
        $x_1_2 = "terra.com.br" ascii //weight: 1
        $x_1_3 = ".php?dest=" ascii //weight: 1
        $x_1_4 = "&radiouser=" ascii //weight: 1
        $x_1_5 = "&amigo=" ascii //weight: 1
        $x_1_6 = "&meunome=" ascii //weight: 1
        $x_1_7 = "</tr></table>" ascii //weight: 1
        $x_1_8 = "WAB\\WAB4\\Wab File Name" ascii //weight: 1
        $x_1_9 = "&email=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Combra_G_2147595062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Combra.G"
        threat_id = "2147595062"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Combra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 5
        $x_1_2 = "musicas/mp3\"" ascii //weight: 1
        $x_1_3 = "arquivos de programas\\internet explorer\\iexplore.exe http:" ascii //weight: 1
        $x_1_4 = "terra.com.br" ascii //weight: 1
        $x_1_5 = "#333399\"><b>Clique" ascii //weight: 1
        $x_1_6 = "</tr></table>" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Combra_H_2147595063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Combra.H"
        threat_id = "2147595063"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Combra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 5
        $x_2_2 = {85 db 7e 2c be 01 00 00 00 8d 45 e4 8b 55 ec 8a 54 3a ff 8b 4d fc 8a 4c 31 ff 32 d1}  //weight: 2, accuracy: High
        $x_1_3 = {50 65 6c 6f 4e 6f 6d 65 0a 54 45 78 65 63 45 4d}  //weight: 1, accuracy: High
        $x_1_4 = "SSL status: \"%s" ascii //weight: 1
        $x_1_5 = "Arial\" color=\"#a50102" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\WAB" ascii //weight: 1
        $x_1_7 = ".com.br" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

