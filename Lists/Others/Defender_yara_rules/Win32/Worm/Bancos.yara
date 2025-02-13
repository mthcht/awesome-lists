rule Worm_Win32_Bancos_A_2147599808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bancos.A"
        threat_id = "2147599808"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "48"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "listerMsnContacts" ascii //weight: 20
        $x_20_2 = "verificaarquivo" ascii //weight: 20
        $x_4_3 = "GOD DAMNIT, the internet" wide //weight: 4
        $x_1_4 = "smtps.uol.com.br" wide //weight: 1
        $x_1_5 = "== 257 then everything is kewl" wide //weight: 1
        $x_1_6 = "Norton AntiVirus" wide //weight: 1
        $x_1_7 = "AlterarRegistro" ascii //weight: 1
        $x_1_8 = "Scripting.FileSystemObject" wide //weight: 1
        $x_1_9 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_10 = "C:\\Arquivos de programas" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 1 of ($x_4_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Bancos_B_2147605813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bancos.B"
        threat_id = "2147605813"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 10
        $x_4_2 = {8b 83 20 03 00 00 4b 00 b8 ?? ?? ?? 00 33 d2 e8 ?? ?? ff ff 8d 45 e8 b9 44 dd 48 00 8b 15 b4 50 49 00 e8 ?? ?? ?? ff 8b 45 e8 e8 ?? ?? ff ff b8 38 dd 48 00 33 d2 e8 ?? ?? ff ff b8 50 dd 48 00 33 d2 e8 ?? ?? ff ff e8 ?? ?? ?? ff 8b 10 ff 52 10 b2 01}  //weight: 4, accuracy: Low
        $x_1_3 = "msn.dat" ascii //weight: 1
        $x_1_4 = "tcefni.dat" ascii //weight: 1
        $x_2_5 = "TEnviaMSNTimer" ascii //weight: 2
        $x_1_6 = {44 53 43 30 ?? ?? ?? 2e 5a 49 50}  //weight: 1, accuracy: Low
        $x_1_7 = "document.getElementById(\"SendMessage\").click()" ascii //weight: 1
        $x_1_8 = "gostei muito dessa foto..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Bancos_D_2147621519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bancos.D"
        threat_id = "2147621519"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Bancanet Empresarial - Windows Interne" ascii //weight: 2
        $x_2_2 = {43 3a 5c 6d 6f 72 70 68 65 75 73 20 06 08 43 3a 5c 6c 69 6d 65 20 06 08 43 3a 5c 62 65 61 72}  //weight: 2, accuracy: High
        $x_2_3 = {6d 69 63 72 6f 73 6f 66 74 61 6e 74 69 2e 65 78 65 [0-12] 6d 72 74 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_2_4 = "Genere un nuevo Codigo en su Dispositivo de Acceso Seguro" ascii //weight: 2
        $x_1_5 = "boundary=\"=_MoreStuf_2relzzzsadvnq1234w3nerasdf" ascii //weight: 1
        $x_1_6 = "C:\\Archivos de programa\\Lavasoft" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Bancos_F_2147622120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bancos.F"
        threat_id = "2147622120"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[autorun]" ascii //weight: 1
        $x_1_2 = ":\\DiskInfo.exe" ascii //weight: 1
        $x_1_3 = "open=diskinfo.exe" ascii //weight: 1
        $x_1_4 = ":\\autorun.inf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Bancos_G_2147622611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bancos.G"
        threat_id = "2147622611"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "82"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ENDERECOS" ascii //weight: 10
        $x_10_2 = "SIZESECAO" ascii //weight: 10
        $x_10_3 = "SMTPHOST" ascii //weight: 10
        $x_10_4 = "LOGINSMTP" ascii //weight: 10
        $x_10_5 = "SENHASMTP" ascii //weight: 10
        $x_10_6 = "POPSERVER" ascii //weight: 10
        $x_10_7 = "EMAILFROM" ascii //weight: 10
        $x_5_8 = "getDominioDaURL" ascii //weight: 5
        $x_5_9 = "downConfig" ascii //weight: 5
        $x_5_10 = "downConfigMSG" ascii //weight: 5
        $x_1_11 = "conf.ini" ascii //weight: 1
        $x_1_12 = "confgAuthentic.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((7 of ($x_10_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

