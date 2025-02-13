rule PWS_MSIL_VB_A_2147633336_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/VB.A"
        threat_id = "2147633336"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hotmail_Hacker.My.Resources" ascii //weight: 1
        $x_1_2 = "Is attempting to hack:" wide //weight: 1
        $x_1_3 = "***You MUST Be Logged In For This To Work***" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_MSIL_VB_B_2147638069_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/VB.B"
        threat_id = "2147638069"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "getMSN75Passwords" ascii //weight: 3
        $x_1_2 = "killproc" ascii //weight: 1
        $x_1_3 = "filezilla" ascii //weight: 1
        $x_2_4 = "AntiSandbox" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_VB_C_2147646747_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/VB.C"
        threat_id = "2147646747"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ezM0NjMxZDIzLWE3NjQtNDI5Yi1iOTRiLWM1MWRkYTk4NDkwYn0sIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49M2U1NjM1MDY5M2Y3MzU1ZQ==" wide //weight: 1
        $x_1_2 = "{74436404-6B81-4FCC-983D-2E4B61E602FE}" wide //weight: 1
        $x_1_3 = "MyFile.exe" ascii //weight: 1
        $x_1_4 = "SmtpClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_MSIL_VB_E_2147653833_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/VB.E"
        threat_id = "2147653833"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Pidgin Stealer Logs!" wide //weight: 2
        $x_1_2 = "[END KEY]" wide //weight: 1
        $x_1_3 = "==FileZilla==" wide //weight: 1
        $x_1_4 = "==CoreFTP==" wide //weight: 1
        $x_1_5 = "==DYNDNS==" wide //weight: 1
        $x_1_6 = "==Opera==" wide //weight: 1
        $x_1_7 = "Stored Chrome Passwords:" wide //weight: 1
        $x_1_8 = "SELECT * FROM moz_logins;" wide //weight: 1
        $x_1_9 = "Product Key" wide //weight: 1
        $x_1_10 = "(Serial)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_VB_F_2147656547_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/VB.F"
        threat_id = "2147656547"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "Projekte\\VB.NET - Papst Stealer.NET\\sTUB\\" ascii //weight: 5
        $x_5_2 = {45 6e 74 73 63 68 6c [0-2] 73 73 65 6c 6e 00 44 65 63 72 79 70 74 55 73 65 72 00 44 65 63 72 79 70 74 50 57 00}  //weight: 5, accuracy: Low
        $x_1_3 = "Splinter Cell Chaos Theory\\Keys" wide //weight: 1
        $x_1_4 = {50 00 6f 00 77 00 65 00 72 00 50 00 72 00 6f 00 64 00 75 00 63 00 65 00 72 00 5c 00 [0-6] 5c 00 55 00 73 00 65 00 72 00 52 00 65 00 67 00}  //weight: 1, accuracy: Low
        $x_1_5 = "Sierra\\CDKey" wide //weight: 1
        $x_1_6 = {49 00 47 00 49 00 20 00 ?? ?? 20 00 52 00 65 00 74 00 61 00 69 00 6c 00 5c 00 43 00 44 00 4b 00 65 00 79 00}  //weight: 1, accuracy: Low
        $x_1_7 = {50 00 61 00 72 00 74 00 69 00 74 00 69 00 6f 00 6e 00 4d 00 61 00 67 00 69 00 63 00 5c 00 [0-6] 5c 00 55 00 73 00 65 00 72 00 49 00 6e 00 66 00 6f 00}  //weight: 1, accuracy: Low
        $x_1_8 = "SILENT HUNTER III\\Keys" wide //weight: 1
        $x_1_9 = "TexasCalc\\License" wide //weight: 1
        $x_1_10 = "Winamp (Serial)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 8 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

