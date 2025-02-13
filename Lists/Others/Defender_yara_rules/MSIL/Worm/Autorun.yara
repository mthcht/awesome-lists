rule Worm_MSIL_Autorun_E_2147637743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Autorun.E"
        threat_id = "2147637743"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "svchostPKS" wide //weight: 1
        $x_1_2 = "2for what you destroy me... ? bye bye" wide //weight: 1
        $x_1_3 = "{98ewr7df645789343465464354e987er46535443488r7}" wide //weight: 1
        $x_1_4 = {5c 00 66 00 6f 00 74 00 6f 00 73 00 2d 00 70 00 65 00 72 00 73 00 6f 00 6e 00 61 00 6c 00 65 00 73 00 2e 00 65 00 78 00 65 00 ?? ?? 5c 00 70 00 65 00 72 00 73 00 6f 00 6e 00 61 00 6c 00 2d 00 70 00 68 00 6f 00 74 00 6f 00 73 00 2e 00 65 00 78 00 65 00 ?? ?? 5c 00 6d 00 70 00 33 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_MSIL_Autorun_F_2147638394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Autorun.F"
        threat_id = "2147638394"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 65 74 5f 66 69 6c 65 5f 6e 61 6d 65 00 75 73 62 5f 63 6f 70 79 00}  //weight: 1, accuracy: High
        $x_1_2 = "[AutoRun]" wide //weight: 1
        $x_1_3 = "action=Ouvrir le dossier pour afficher les fichiers" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_MSIL_Autorun_G_2147639482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Autorun.G"
        threat_id = "2147639482"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "pidginstealer" ascii //weight: 2
        $x_1_2 = "Software\\IMVU\\Password" wide //weight: 1
        $x_1_3 = "SELECT * FROM moz_logins;" wide //weight: 1
        $x_3_4 = "LethalInjectionStub.Resources" ascii //weight: 3
        $x_1_5 = "[autorun]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_MSIL_Autorun_H_2147639650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Autorun.H"
        threat_id = "2147639650"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AddRemoveUSBHandler" ascii //weight: 1
        $x_1_2 = "USBWerm" ascii //weight: 1
        $x_1_3 = "\\autorun.inf" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_MSIL_Autorun_I_2147639652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Autorun.I"
        threat_id = "2147639652"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://adgrabber.110mb.com/todo.txt" wide //weight: 1
        $x_1_2 = "[autorun]" wide //weight: 1
        $x_1_3 = "open=.\\Highspeed drivers.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_MSIL_Autorun_J_2147641098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Autorun.J"
        threat_id = "2147641098"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "[autorun]" wide //weight: 2
        $x_4_2 = "yrfevE8hm69TWbOwaMl3.exe" wide //weight: 4
        $x_4_3 = "-=-Public Lonely Logger Logs V1.0-=-" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_MSIL_Autorun_O_2147653512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Autorun.O"
        threat_id = "2147653512"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "199.71.212.91" wide //weight: 1
        $x_1_2 = "[UAC deactivated" wide //weight: 1
        $x_1_3 = "[DDoS started on" wide //weight: 1
        $x_1_4 = "[Process killed" wide //weight: 1
        $x_1_5 = {73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 2e 00 65 00 78 00 65 00 [0-3] 2d 00 72 00 20 00 2d 00 74 00 20 00 30 00}  //weight: 1, accuracy: Low
        $x_1_6 = "open=autorun.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Worm_MSIL_Autorun_P_2147653518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Autorun.P"
        threat_id = "2147653518"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&flagirc=" wide //weight: 1
        $x_1_2 = "open=autorun.exe" wide //weight: 1
        $x_1_3 = "/dom/update.php" wide //weight: 1
        $x_1_4 = "/dom/result.php" wide //weight: 1
        $x_1_5 = "/download/msnmsgs.exe" wide //weight: 1
        $x_1_6 = " into microsoft folder" wide //weight: 1
        $x_1_7 = ".dombot.co.cc" wide //weight: 1
        $x_1_8 = "killed! ADDIO!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Worm_MSIL_Autorun_Q_2147653830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Autorun.Q"
        threat_id = "2147653830"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "clowzer@" wide //weight: 10
        $x_10_2 = "smtp.menara.ma" wide //weight: 10
        $x_10_3 = "shellexecute=system.exe" wide //weight: 10
        $x_1_4 = "e:\\system.exe" wide //weight: 1
        $x_1_5 = "e:\\autorun.inf" wide //weight: 1
        $x_1_6 = "e:\\reg.exe" wide //weight: 1
        $x_1_7 = "f:\\system.exe" wide //weight: 1
        $x_1_8 = "f:\\autorun.inf" wide //weight: 1
        $x_1_9 = "f:\\reg.exe" wide //weight: 1
        $x_1_10 = "<br> ip : <font" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_MSIL_Autorun_R_2147654074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Autorun.R"
        threat_id = "2147654074"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00 ?? ?? 6f 00 70 00 65 00 6e 00 3d 00 ?? ?? 73 00 68 00 65 00 6c 00 6c 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_2 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 65 00 73 00 74 00 6f 00 72 00 65 00 ?? ?? 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 53 00 52 00}  //weight: 1, accuracy: Low
        $x_1_3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 41 00 64 00 76 00 61 00 6e 00 63 00 65 00 64 00 ?? ?? 48 00 69 00 64 00 64 00 65 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_4 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 74 00 63 00 5c 00 68 00 6f 00 73 00 74 00 73 00 [0-48] 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 77 00 77 00 77 00 2e 00 76 00 69 00 72 00 75 00 73 00 74 00 6f 00 74 00 61 00 6c 00 2e 00 63 00 6f 00 6d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_MSIL_Autorun_S_2147655429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Autorun.S"
        threat_id = "2147655429"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5b 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00 [0-5] 6f 00 70 00 65 00 6e 00 3d 00}  //weight: 10, accuracy: Low
        $x_1_2 = "HttpFlood" ascii //weight: 1
        $x_1_3 = "UDPFlood" ascii //weight: 1
        $x_1_4 = "width='1' height='1'" wide //weight: 1
        $x_1_5 = "Victim Connected!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_MSIL_Autorun_U_2147657930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Autorun.U"
        threat_id = "2147657930"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "USER cr4ckr0x" wide //weight: 5
        $x_5_2 = "shellexecute=autorun.exe" wide //weight: 5
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" wide //weight: 1
        $x_1_4 = "Select * From Win32_Process" wide //weight: 1
        $x_1_5 = "TargetInstance ISA 'Win32_USBControllerdevice'" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_MSIL_Autorun_V_2147657958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Autorun.V"
        threat_id = "2147657958"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "MailAddressCollection" ascii //weight: 5
        $x_5_2 = "DisableTaskMgr" wide //weight: 5
        $x_5_3 = "select * from win32_share" wide //weight: 5
        $x_5_4 = "Melt.bat" wide //weight: 5
        $x_1_5 = "gethashcode" ascii //weight: 1
        $x_1_6 = "set_Key" ascii //weight: 1
        $x_1_7 = "AntiKeyscrambler" ascii //weight: 1
        $x_1_8 = "[autorun]" wide //weight: 1
        $x_1_9 = "autorun.inf" wide //weight: 1
        $x_1_10 = "shellexecute=" wide //weight: 1
        $x_1_11 = "bitdefender" ascii //weight: 1
        $x_1_12 = "spersk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_MSIL_Autorun_X_2147658404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Autorun.X"
        threat_id = "2147658404"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "[autorun]" wide //weight: 2
        $x_2_2 = "Passwords|FileZilla|" wide //weight: 2
        $x_2_3 = "\\.purple\\accounts.xml" wide //weight: 2
        $x_2_4 = "SELECT * FROM moz_logins;" wide //weight: 2
        $x_1_5 = "|Infected" wide //weight: 1
        $x_1_6 = "Flooding:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_MSIL_Autorun_Z_2147658452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Autorun.Z"
        threat_id = "2147658452"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".yoyo.pl/autorun.inf" wide //weight: 2
        $x_1_2 = ".SmartIrc4net" ascii //weight: 1
        $x_1_3 = "GoldTrojan" ascii //weight: 1
        $x_1_4 = "\\Setup\\svchost.exe" wide //weight: 1
        $x_1_5 = "\\gammess\\svchost.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

