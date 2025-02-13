rule Backdoor_Win32_Pahador_ABG_2147595172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Pahador.gen!ABG"
        threat_id = "2147595172"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Pahador"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "39"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "xxx.jpg" ascii //weight: 10
        $x_10_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_3 = "\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 10
        $x_1_4 = "#del [sciezka do pliku] - Usuwa plik" ascii //weight: 1
        $x_1_5 = "#deldir [sciezka do folderu] - Usuwa katalog, wraz z wszystkimi plikami i podfolderami." ascii //weight: 1
        $x_1_6 = "#directory c:\\program files\\ - Pokazuje zawarto" ascii //weight: 1
        $x_1_7 = "#kill - Zabija proces keyloggera." ascii //weight: 1
        $x_1_8 = "#put [mail,ftp] c:\\plik.txt - Wysyla plik na ftp lub mail." ascii //weight: 1
        $x_1_9 = "VisualShock Keylogger 3" ascii //weight: 1
        $x_1_10 = "Log z VisualShock Keylogger 3" ascii //weight: 1
        $x_1_11 = "VisualShock Keylogger 3 pomoc:" ascii //weight: 1
        $x_1_12 = "any przez VisualShock Keylogger" ascii //weight: 1
        $x_1_13 = "Nagranie z mikrofonu pochodzi z VisualShock Keylogger 3" ascii //weight: 1
        $x_1_14 = "AuthorizedApplications" ascii //weight: 1
        $x_1_15 = "DisableTaskMgr" ascii //weight: 1
        $x_1_16 = "FirewallPolicy" ascii //weight: 1
        $x_1_17 = "CallNextHookEx" ascii //weight: 1
        $x_1_18 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_19 = "InternetGetConnectedState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 9 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Pahador_ABI_2147595192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Pahador.gen!ABI"
        threat_id = "2147595192"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Pahador"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cellpadding=\"0\" cellspacing=\"1\"><tr><td bgcolor=\"white\"><font size=\"2\" color=\"#445A7D\">" ascii //weight: 1
        $x_1_2 = "<center><a href=\"http://www.vsk.100.com.pl/faq.html\"> FaQ </a>" ascii //weight: 1
        $x_1_3 = "<a><i>Godzina: " ascii //weight: 1
        $x_1_4 = "SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" ascii //weight: 1
        $x_1_5 = "<a href=\"http://www.vsk.100.com.pl/formularz.html\">Zglos blad</a>" ascii //weight: 1
        $x_1_6 = "<table align=\"center\" width=\"100%\" border=\"0\" height=\"0\" bgcolor=\"#xxxxx\"" ascii //weight: 1
        $x_1_7 = "<h1> Zawartosc loga: </h1>" ascii //weight: 1
        $x_1_8 = "cellpadding=\"0\"" ascii //weight: 1
        $x_1_9 = "tempst.exe" ascii //weight: 1
        $x_1_10 = "<font color=\"#333399\"><b>Nie mozna otworzyc schowka.</b></font><br>" ascii //weight: 1
        $x_1_11 = "cellspacing=\"0\"><tr><td bgcolor=\"white\"><font size=\"2\" color=\"#445A7D\">" ascii //weight: 1
        $x_1_12 = "<font color=\"#333399\"><b>Tekst w schowku: " ascii //weight: 1
        $x_1_13 = "Aby uzyskac liste polece" ascii //weight: 1
        $x_1_14 = "<br><b>[ Aktywne okno: <i>" ascii //weight: 1
        $x_1_15 = ">[<i> Pulpit</i>]</b><br>" ascii //weight: 1
        $x_1_16 = "<br><b>[<i> Pulpit</i>]</b><br>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

