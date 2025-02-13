rule Worm_Win32_Brontok_2147572220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Brontok@mm"
        threat_id = "2147572220"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Brontok"
        severity = "Critical"
        info = "mm: mass mailer worm"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "            Nobron & Romdil -->> Kicked by The Amazing Brontok" ascii //weight: 1
        $x_1_2 = "         Nobron = Satria Dungu = Nothing !!!" ascii //weight: 1
        $x_1_3 = "         Romdil = Tukang Jiplak = Nothing !!!" ascii //weight: 1
        $x_1_4 = "    Nobron & Romdil = Otak Kosong, Mulut Besar, Cuma Bisa Baca Puisi" ascii //weight: 1
        $x_1_5 = "   BRONTOK.C[22]" ascii //weight: 1
        $x_1_6 = " ~Brontok~Back~Log~" ascii //weight: 1
        $x_1_7 = " ~Brontok~Is~The~Best~" ascii //weight: 1
        $x_1_8 = " ~Brontok~Log~" ascii //weight: 1
        $x_1_9 = " ~Brontok~Network~" ascii //weight: 1
        $x_1_10 = " ~Brontok~Payload~Show~" ascii //weight: 1
        $x_1_11 = " ~Brontok~Serv~" ascii //weight: 1
        $x_1_12 = " ~Brontok~SpreadMail~" ascii //weight: 1
        $x_1_13 = " ~Brontok~To~LoadingInfo~" ascii //weight: 1
        $x_1_14 = "######################### BRONTOK.C[22] #########################" ascii //weight: 1
        $x_1_15 = "#JowoBot-CrackHost" ascii //weight: 1
        $x_1_16 = "#JowoBot-VM Community" ascii //weight: 1
        $x_1_17 = "Brontok.A" ascii //weight: 1
        $x_1_18 = "BrontokForm" ascii //weight: 1
        $x_1_19 = "TmrBrontok" ascii //weight: 1
        $x_1_20 = "Brontok.A.HVM31" ascii //weight: 1
        $x_1_21 = "BRONTOK_A" ascii //weight: 1
        $x_1_22 = "#INI_Brontok_A" wide //weight: 1
        $x_1_23 = "By: HVM31" wide //weight: 1
        $x_1_24 = "-- JowoBot #VM Community --" wide //weight: 1
        $x_1_25 = "\\about.Brontok.A.html" wide //weight: 1
        $x_1_26 = "\\Bron.tok-" wide //weight: 1
        $x_1_27 = "\\Bron.tok.A" wide //weight: 1
        $x_1_28 = "\\Kosong.Bron.Tok.txt" wide //weight: 1
        $x_1_29 = "\\Ok-SendMail-Bron-tok" wide //weight: 1
        $x_1_30 = "# JowoBot-CrackHosts" wide //weight: 1
        $x_1_31 = "*\\AF:\\VPROJECT\\STABLE\\17-Beta\\BRONTOK.A\\Brontok.A.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Brontok_B_2147572409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Brontok@mm.gen!B"
        threat_id = "2147572409"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Brontok"
        severity = "Critical"
        info = "mm: mass mailer worm"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SENSASI_A" ascii //weight: 1
        $x_1_2 = "#INI_Sensasi_A" wide //weight: 1
        $x_1_3 = "\\SensFoldNetDomList.txt" ascii //weight: 1
        $x_1_4 = "Sensasi.A" ascii //weight: 1
        $x_1_5 = "SensasiForm" ascii //weight: 1
        $x_1_6 = "TmrBrontok" ascii //weight: 1
        $x_1_7 = "\\Ok-SendMail-Sens-asi" wide //weight: 1
        $x_1_8 = "*\\AF:\\VPROJECT\\OK\\5\\SENSASI.A\\Sensasi.A.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Brontok_C_2147582773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Brontok@mm.gen!C"
        threat_id = "2147582773"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Brontok"
        severity = "Critical"
        info = "mm: mass mailer worm"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "190"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Notepad.exe C:\\Puisi.txt" wide //weight: 100
        $x_50_2 = "PersistMoniker=file://" wide //weight: 50
        $x_20_3 = "Wahai Para Wakil Rakyat...." ascii //weight: 20
        $x_10_4 = "aksika" ascii //weight: 10
        $x_10_5 = "MRHELL~1" wide //weight: 10
        $x_10_6 = "MrHelloween" wide //weight: 10
        $x_10_7 = "Empty.pif" wide //weight: 10
        $x_10_8 = "\\Folder.htt" wide //weight: 10
        $x_10_9 = "kere.exe" wide //weight: 10
        $x_10_10 = "SCRNSAVE.EXE" wide //weight: 10
        $x_10_11 = "Tangisku bukan milikmu" wide //weight: 10
        $x_10_12 = "Tangismu adalah milikku" wide //weight: 10
        $x_10_13 = "Tak ada lagi yang ku kejar saat ini" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 9 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_20_*) and 7 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 4 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Brontok_FFR_2147601656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Brontok.FFR"
        threat_id = "2147601656"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Brontok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\W32.Moontox Bro B-1\\PROJECT1.VBP" wide //weight: 5
        $x_5_2 = "TopinsutkiCommunity" wide //weight: 5
        $x_1_3 = "\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
        $x_1_4 = "\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = "\\Windows\\CurrentVersion\\Explorer\\Advanced" wide //weight: 1
        $x_1_6 = "HideFileExt" wide //weight: 1
        $x_1_7 = "SuperHidden" wide //weight: 1
        $x_1_8 = "\\Windows\\CurrentVersion\\Policies\\System" wide //weight: 1
        $x_1_9 = "DisableRegistryTools" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Brontok_GA_2147602386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Brontok.GA"
        threat_id = "2147602386"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Brontok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 7f 00 04 00 04 68 ff 04 58 ff 0a 80 00 08 00 04 58 ff fb e9 48 ff 55 70 7a ff 36 04 00 68 ff 58 ff 04 46 ff 10 f8 06 08 00 6b 46 ff f4 ff c6 1c 8e 00 6b 7a ff f4 02 c1 f4 00 c6 1c 6b 00 04 40 ff f4 03 1b e7 00 10 18 07 08 00 f5 00 00 00 00 3e 40 ff 46 68 ff 0a 29 00 08 00 74 38 ff 35 68 ff 1e 8e 00 04 40 ff f4 03 1b e8 00 10 18 07 08 00 f5 00 00 00 00 3e 40 ff 46 68 ff}  //weight: 1, accuracy: High
        $x_1_2 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c 00 00 00 00 4d 65 74 68 43 61 6c 6c 45 6e 67 69 6e 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Brontok_MBQ_2147932984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Brontok.MBQ!MTB"
        threat_id = "2147932984"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Brontok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 7f 40 00 00 f8 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 00 7a 40 00 e8 78 40 00 00 20 40 00 78 00 00 00 7d 00 00 00 82 00 00 00 83}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

