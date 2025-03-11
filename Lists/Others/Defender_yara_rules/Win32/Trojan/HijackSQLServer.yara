rule Trojan_Win32_HijackSQLServer_A_2147823013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HijackSQLServer.A"
        threat_id = "2147823013"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HijackSQLServer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = ".downloadfile(" wide //weight: 10
        $x_10_3 = "net.webclient" wide //weight: 10
        $x_1_4 = "wmic process call create" wide //weight: 1
        $x_1_5 = "start " wide //weight: 1
        $x_1_6 = "start-process " wide //weight: 1
        $x_1_7 = "wmicimv2/win32_process" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_HijackSQLServer_B_2147838283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HijackSQLServer.B"
        threat_id = "2147838283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HijackSQLServer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 6d 00 64 00 [0-255] 2f 00 63 00}  //weight: 10, accuracy: Low
        $x_1_2 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 77 00 65 00 62 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 20 00 [0-16] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = {69 00 77 00 72 00 20 00 [0-16] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_10_4 = {2d 00 6f 00 75 00 74 00 66 00 69 00 6c 00 65 00 [0-255] 20 00 3e 00 20 00 [0-255] 20 00 26 00 20 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_HijackSQLServer_AB_2147841735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HijackSQLServer.AB"
        threat_id = "2147841735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HijackSQLServer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "net.webclient" wide //weight: 10
        $x_10_3 = ".downloadstring(" wide //weight: 10
        $x_5_4 = "invoke-expression" wide //weight: 5
        $x_5_5 = "iex" wide //weight: 5
        $n_50_6 = "chocolatey" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_HijackSQLServer_D_2147907152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HijackSQLServer.D"
        threat_id = "2147907152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HijackSQLServer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe" wide //weight: 1
        $x_1_2 = "powershell.exe" wide //weight: 1
        $x_1_3 = "wmicimv2/win32_process " wide //weight: 1
        $x_1_4 = "process call create " wide //weight: 1
        $x_1_5 = "start-process " wide //weight: 1
        $x_1_6 = "c:\\users\\public" wide //weight: 1
        $x_1_7 = "winrm" wide //weight: 1
        $x_1_8 = "echo" wide //weight: 1
        $x_1_9 = "invoke-webrequest" wide //weight: 1
        $x_1_10 = "iwr " wide //weight: 1
        $x_1_11 = "-OutFile" wide //weight: 1
        $x_1_12 = "downloadfile" wide //weight: 1
        $x_1_13 = "downloadstring" wide //weight: 1
        $x_1_14 = "frombase64string" wide //weight: 1
        $n_100_15 = "\\webpresented.wpcrm.console.exe" wide //weight: -100
        $n_100_16 = "cap_verify.bat" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

rule Trojan_Win32_HijackSQLServer_F_2147910271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HijackSQLServer.F"
        threat_id = "2147910271"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HijackSQLServer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "110"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_100_2 = "sqbuahyabwbragualqbdag8abqbtageabgbkacaalqbtagmacgbpahaadabcagwabwbjagsaiab7acaacabhahiayqbtacaakaakahuacgbsackaiaakagyaaqbsagu" wide //weight: 100
        $x_100_3 = "jabwahiabwbjaguacwbzae4ayqbtaguacwagad0aiabhaguadaatafaacgbvagmazqbzahmaiab8acaauwblagwazqbjahqalqbpagiaagb" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

