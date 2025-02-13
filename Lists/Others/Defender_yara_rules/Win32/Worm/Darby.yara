rule Worm_Win32_Darby_A_2147489187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Darby.A"
        threat_id = "2147489187"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Darby"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = "symantec" wide //weight: 10
        $x_10_3 = "messagelab" wide //weight: 10
        $x_10_4 = "\\Virus\\Bardiel.D\\Sag.vbp" wide //weight: 10
        $x_10_5 = "\\Image0X.scr" wide //weight: 10
        $x_1_6 = "Security-2004-Update.exe" wide //weight: 1
        $x_1_7 = "The Hacker Antivirus 5.7.exe" wide //weight: 1
        $x_1_8 = "Screen saver christina aguilera naked.exe" wide //weight: 1
        $x_1_9 = "Microsoft KeyGenerator-Allmost all microsoft stuff.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Darby_2147580882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Darby"
        threat_id = "2147580882"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Darby"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Escritorio" wide //weight: 1
        $x_1_2 = "svhost" wide //weight: 1
        $x_1_3 = "Bardiel" wide //weight: 1
        $x_1_4 = "Proyecto" wide //weight: 1
        $x_1_5 = "conect" wide //weight: 1
        $x_1_6 = "cerro" wide //weight: 1
        $x_1_7 = "NICK" wide //weight: 1
        $x_1_8 = "USER" wide //weight: 1
        $x_1_9 = "terra.com" wide //weight: 1
        $x_1_10 = "hotmail.com" wide //weight: 1
        $x_1_11 = "zonav.org" wide //weight: 1
        $x_1_12 = "aol.com" wide //weight: 1
        $x_1_13 = "msn.com" wide //weight: 1
        $x_1_14 = "latinmail.com" wide //weight: 1
        $x_1_15 = "yahoo.com" wide //weight: 1
        $x_1_16 = "startmedia.com" wide //weight: 1
        $x_1_17 = "prodigy.mx" wide //weight: 1
        $x_1_18 = "users.undernet.org" wide //weight: 1
        $x_1_19 = "crack.exe" wide //weight: 1
        $x_1_20 = "Exploit.exe" wide //weight: 1
        $x_2_21 = "Cracker.exe" wide //weight: 2
        $x_2_22 = "generator.exe" wide //weight: 2
        $x_1_23 = "Archivos de programa" ascii //weight: 1
        $x_1_24 = "InternetGetConnectedState" ascii //weight: 1
        $x_1_25 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_26 = "WSACancelBlockingCall" ascii //weight: 1
        $x_3_27 = {66 35 07 00 0f bf c0 50 8d 4d}  //weight: 3, accuracy: High
        $x_3_28 = "ossw=((" wide //weight: 3
        $x_3_29 = "Thaspfub" wide //weight: 3
        $x_3_30 = "Jnduhthas" wide //weight: 3
        $x_2_31 = "Pnichpt" wide //weight: 2
        $x_2_32 = "Druubis" wide //weight: 2
        $x_3_33 = "Whkndnbt" wide //weight: 3
        $x_3_34 = "~Shhkt" wide //weight: 3
        $x_2_35 = "T~tsbj" wide //weight: 2
        $x_3_36 = "CntfekbUb" wide //weight: 3
        $x_2_37 = "ricbuibs" wide //weight: 2
        $x_2_38 = "[Es6)e" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 23 of ($x_1_*))) or
            ((3 of ($x_2_*) and 21 of ($x_1_*))) or
            ((4 of ($x_2_*) and 19 of ($x_1_*))) or
            ((5 of ($x_2_*) and 17 of ($x_1_*))) or
            ((6 of ($x_2_*) and 15 of ($x_1_*))) or
            ((7 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_3_*) and 24 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 22 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 20 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 18 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_3_*) and 6 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_3_*) and 21 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 19 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 17 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_3_*) and 5 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_3_*) and 6 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_3_*) and 7 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_3_*) and 18 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 16 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 14 of ($x_1_*))) or
            ((3 of ($x_3_*) and 3 of ($x_2_*) and 12 of ($x_1_*))) or
            ((3 of ($x_3_*) and 4 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_3_*) and 5 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_3_*) and 6 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_3_*) and 7 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_3_*) and 15 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((4 of ($x_3_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((4 of ($x_3_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_3_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_3_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_3_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_3_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_3_*) and 12 of ($x_1_*))) or
            ((5 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((5 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((5 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((5 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_3_*) and 6 of ($x_2_*))) or
            ((6 of ($x_3_*) and 9 of ($x_1_*))) or
            ((6 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((6 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((6 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((6 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_3_*) and 5 of ($x_2_*))) or
            ((7 of ($x_3_*) and 6 of ($x_1_*))) or
            ((7 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((7 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((7 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

