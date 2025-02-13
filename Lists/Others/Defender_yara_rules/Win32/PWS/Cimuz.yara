rule PWS_Win32_Cimuz_C_2147595272_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Cimuz.C"
        threat_id = "2147595272"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Cimuz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Explorer\\browser helper obJects\\" ascii //weight: 1
        $x_1_2 = "Conformance ranking" ascii //weight: 1
        $x_4_3 = "1897[2], and dubbed \"plasma\"" ascii //weight: 4
        $x_2_4 = {2e 70 68 70 73 00 00 6d 61 69 6e 2e 70 68 70}  //weight: 2, accuracy: High
        $x_2_5 = {79 65 73 00 45 6e 61 62 6c 65 20 42 72 6f 77 73}  //weight: 2, accuracy: High
        $x_2_6 = {c6 85 00 ff ff ff 50 c6 85 fc ef ff ff 7a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Cimuz_E_2147606492_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Cimuz.E"
        threat_id = "2147606492"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Cimuz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 12 6a 00 6a 01 5f 57 ff 35 ?? ?? 00 10 ff d3 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7d 3c 03 fd 81 3f 50 45 00 00 0f 85 0e 01 00 00 8b 35 ?? ?? 00 10 6a 04 68 00 20 00 00 ff 77 50 ff 77 34 ff d6 8b d8 85 db}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 43 0c 03 44 24 10 50 ff 15 ?? ?? 00 10 83 f8 ff}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 04 77 f7 c1 00 00 00 04 8d 04 42 8b 34 85 ?? ?? 00 10 74 06 81 ce 00 02 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {99 5b f7 fb 30 14 (31|39) 41 3b (cf|ce) 72 f0 04 00 8b c1 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_Cimuz_I_2147611165_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Cimuz.I"
        threat_id = "2147611165"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Cimuz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {76 10 8b c1 6a 05 99 ?? f7 ?? 30 14 ?? 41 3b ?? 72 f0 8b 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? bd ?? ?? ?? ?? ?? 55 ff d6 ?? e8 ?? ?? ff ff}  //weight: 5, accuracy: Low
        $x_1_2 = {3d c5 f8 ae ca}  //weight: 1, accuracy: High
        $x_1_3 = {52 54 5f 52 45 47 44 4c 4c 00}  //weight: 1, accuracy: High
        $x_1_4 = {52 54 5f 44 4c 4c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Cimuz_J_2147611499_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Cimuz.J"
        threat_id = "2147611499"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Cimuz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 05 99 5b f7 fb 30 14 39 41 3b ce 72 f0}  //weight: 1, accuracy: High
        $x_1_2 = {6a 05 5f 8d 34 01 8b c1 99 f7 ff 30 16 41 3b cb 72 eb}  //weight: 1, accuracy: High
        $x_2_3 = {52 54 5f 52 45 47 44 4c 4c 00}  //weight: 2, accuracy: High
        $x_2_4 = {73 67 64 60 6c 6d 2c 67 68 6c 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Cimuz_M_2147633337_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Cimuz.M!dll"
        threat_id = "2147633337"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Cimuz"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FoxMailPassword" ascii //weight: 1
        $x_2_2 = "Passwords of Auto Complete" ascii //weight: 2
        $x_2_3 = "IE/FTP/OutLook Password" ascii //weight: 2
        $x_1_4 = "WinNT/Win2K Login" ascii //weight: 1
        $x_1_5 = "5e7e8100" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Cimuz_N_2147637322_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Cimuz.N"
        threat_id = "2147637322"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Cimuz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gmail-smtp-in.l.google.com" ascii //weight: 1
        $x_2_2 = "Firefox account data" ascii //weight: 2
        $x_1_3 = "PK11_CheckUserPassword" ascii //weight: 1
        $x_3_4 = "SOFTWARE\\Clients\\StartMenuInternet\\firefox.exe\\shell\\open\\command" ascii //weight: 3
        $x_2_5 = "Internet Explorer account data" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Cimuz_O_2147638306_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Cimuz.O"
        threat_id = "2147638306"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Cimuz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "webpost64.dll" ascii //weight: 2
        $x_1_2 = "HTTPMail Password2" ascii //weight: 1
        $x_2_3 = "_KeyLog.txt" ascii //weight: 2
        $x_3_4 = "Content-Disposition: form-data; name=\"strPhoto\"; filename=\"\\30748_%s\"" ascii //weight: 3
        $x_2_5 = "IE:Password-Protected sites" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Cimuz_A_2147806787_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Cimuz.gen!A"
        threat_id = "2147806787"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Cimuz"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "No installer*.exe found! exiting..." ascii //weight: 2
        $x_5_2 = {3a 2a 3a 45 6e 61 62 6c 65 64 3a 00 53 79 73 74 65 6d 5c 43 75 72 72 65 6e}  //weight: 5, accuracy: High
        $x_1_3 = "CurrentVersion\\Control Panel\\load" ascii //weight: 1
        $x_2_4 = "Type: application/x-www-form-urlencoded" ascii //weight: 2
        $x_2_5 = "FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" ascii //weight: 2
        $x_1_6 = "\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 1
        $x_3_7 = "browser helper obJects" ascii //weight: 3
        $x_1_8 = "Enable Browser Extensions" ascii //weight: 1
        $x_2_9 = "7836z4D99-" ascii //weight: 2
        $x_2_10 = "78364D99-" ascii //weight: 2
        $x_2_11 = {41 70 70 49 44 5c 5c 00 7a 7b 37 33 33 36 34 44}  //weight: 2, accuracy: High
        $x_2_12 = "RT_KEYLOGGER" ascii //weight: 2
        $x_3_13 = {21 20 65 78 69 74 69 6e 67 2e 2e 2e [0-15] 45 52 52 4f 52 5f 49 4e 5f 50 41 52 41 4d 53 5f 49 44}  //weight: 3, accuracy: Low
        $x_2_14 = {50 41 52 41 4d 53 5f 49 44 00 00 7a 2d}  //weight: 2, accuracy: High
        $x_2_15 = "%s(select): %s [checked]" ascii //weight: 2
        $x_1_16 = "daemon" ascii //weight: 1
        $x_2_17 = "WAI Conformance ranking" ascii //weight: 2
        $x_2_18 = "Web Accessibility Initiative (WAI) W" ascii //weight: 2
        $x_2_19 = "civilians if it rejects outside help." ascii //weight: 2
        $x_1_20 = "%s(textarea): %s" ascii //weight: 1
        $x_1_21 = "220d5cc1" ascii //weight: 1
        $x_1_22 = "5e7e8100" ascii //weight: 1
        $x_1_23 = "Action: %s" ascii //weight: 1
        $x_1_24 = "b9819c52" ascii //weight: 1
        $x_1_25 = "e161255a" ascii //weight: 1
        $x_1_26 = "if%d : %s" ascii //weight: 1
        $x_1_27 = "Internet Account Manager\\Accounts" ascii //weight: 1
        $x_1_28 = "Protected storage service not started" ascii //weight: 1
        $x_1_29 = "textarea): %s" ascii //weight: 1
        $x_1_30 = "SKIPPED TAN" ascii //weight: 1
        $x_2_31 = "404 Not Found" ascii //weight: 2
        $x_1_32 = "e;element" ascii //weight: 1
        $x_1_33 = "a;address" ascii //weight: 1
        $x_1_34 = "shot.html" ascii //weight: 1
        $x_1_35 = "app;append" ascii //weight: 1
        $x_1_36 = "m;message" ascii //weight: 1
        $x_1_37 = "rep;replace" ascii //weight: 1
        $x_1_38 = "add;additional" ascii //weight: 1
        $x_1_39 = "e;equals" ascii //weight: 1
        $x_1_40 = "message;messagebox" ascii //weight: 1
        $x_1_41 = "[POPUP] = " ascii //weight: 1
        $x_2_42 = "; logindata: " ascii //weight: 2
        $x_1_43 = "input -r name" ascii //weight: 1
        $x_1_44 = "excl;exclude" ascii //weight: 1
        $x_1_45 = "postbank.de" ascii //weight: 1
        $x_1_46 = "tancuter" ascii //weight: 1
        $x_1_47 = "b;back;background" ascii //weight: 1
        $x_1_48 = "-e title" ascii //weight: 1
        $x_1_49 = "n;navigate" ascii //weight: 1
        $x_1_50 = "navigate" ascii //weight: 1
        $x_1_51 = "wasessage" ascii //weight: 1
        $x_1_52 = "CompID: %s" ascii //weight: 1
        $x_2_53 = "tan;Transaktionsnummer" ascii //weight: 2
        $x_1_54 = "Buttons pressed: " ascii //weight: 1
        $x_1_55 = "-e input -r name=" ascii //weight: 1
        $x_1_56 = "taloinata" ascii //weight: 1
        $x_1_57 = "FIPP]: URL" ascii //weight: 1
        $x_2_58 = "Tassimo hot drink mashine Shopping and Price" ascii //weight: 2
        $x_2_59 = "Passprot sites" ascii //weight: 2
        $x_1_60 = "<>- Microsoft Internet Explorer" ascii //weight: 1
        $x_1_61 = "[e-gold mail]: " ascii //weight: 1
        $x_1_62 = "e td -s 1 -h 'e-mail:' -l 300 -f" ascii //weight: 1
        $x_1_63 = "AccountID" ascii //weight: 1
        $x_1_64 = "e-gold.com/acct/acct.asp" ascii //weight: 1
        $x_3_65 = "AutoCompletePasswords:" ascii //weight: 3
        $x_3_66 = "IEAutoCompleteFields" ascii //weight: 3
        $x_3_67 = "ver=%s&lg=%s" ascii //weight: 3
        $x_1_68 = "A:S /Q /F c" ascii //weight: 1
        $x_1_69 = "del /A:S /Q /F c" ascii //weight: 1
        $x_1_70 = "del /S /Q %SYSTEMROOT" ascii //weight: 1
        $x_1_71 = "net_insll" ascii //weight: 1
        $x_5_72 = "lg=%s&phid=%s" ascii //weight: 5
        $x_2_73 = "an angular display face that shows witty" ascii //weight: 2
        $x_2_74 = "and bought tit and clit sucking tools for used copying mashine" ascii //weight: 2
        $x_2_75 = "and clit sucking tools for used copying mashine supplier directory" ascii //weight: 2
        $x_2_76 = "art of making music with Macs. Mashine is an angular" ascii //weight: 2
        $x_2_77 = "be of service in your quest to master the art of making music" ascii //weight: 2
        $x_2_78 = "3294u03u089y7dfyefr" ascii //weight: 2
        $x_2_79 = "4ur34j0u8reu8gu98erfg" ascii //weight: 2
        $x_2_80 = "zu9309ur8u389rdhes" ascii //weight: 2
        $x_2_81 = "can expect to see regular use of our tit suckers - we were so pleased" ascii //weight: 2
        $x_2_82 = "copying mashine suppliers from China and around the world" ascii //weight: 2
        $x_2_83 = "David's work. Member pages contain valuable" ascii //weight: 2
        $x_2_84 = "directory - over 3000000 registered importers and exporters" ascii //weight: 2
        $x_2_85 = "ejifj8493y9fy34yf7yy84r" ascii //weight: 2
        $x_2_86 = "y9fy34yf7yy84r" ascii //weight: 2
        $x_2_87 = "adressed mashine saying \"here I am! ... Exactly" ascii //weight: 2
        $x_2_88 = "ahrink mashine ashrink mashine sahrink mashine whrink" ascii //weight: 2
        $x_2_89 = "and census data / Statistique Canada (www.statcan" ascii //weight: 2
        $x_2_90 = "and Translation <doc at arabeyes dot org>; Subject: the mashine" ascii //weight: 2
        $x_2_91 = "Arafat Medini <lumina at silverpen dot de>; Date: Tue,  happy" ascii //weight: 2
        $x_2_92 = "Shop, pure Costa Rica bean, single farm gourmet" ascii //weight: 2
        $x_2_93 = "Shrink. animal surprise mug ... shrink mashine4 shrink mashine" ascii //weight: 2
        $x_2_94 = "understand why 2 NIC's on > one mashine need two subnets" ascii //weight: 2
        $x_2_95 = "and Windchill PDMLink. PTC's PLM software" ascii //weight: 2
        $x_2_96 = "de Ven, hoofd Nationale rekeningen binnen het CBS" ascii //weight: 2
        $x_2_97 = "&user=456" ascii //weight: 2
        $x_3_98 = "del /S /Q %SYSTEMROOT%  %PROGRAMFILES" ascii //weight: 3
        $x_2_99 = "additional information about the A-Prompt" ascii //weight: 2
        $x_2_100 = "A-Prompt on Jan. 31, 2002. The CAMO, a Francophone labour" ascii //weight: 2
        $x_2_101 = "la main-d'oeuvre pour personnes handicapees (CAMO), introduced" ascii //weight: 2
        $x_2_102 = "c:\\clearsdingdrfive" ascii //weight: 2
        $x_2_103 = "djrgjeigjeoirgjerirg.txt" ascii //weight: 2
        $x_3_104 = "zContent-Type: application/x-www-form-urlencoded" ascii //weight: 3
        $x_1_105 = "HTTPMail Password" ascii //weight: 1
        $x_1_106 = "emailaddr" ascii //weight: 1
        $x_1_107 = "popusernam" ascii //weight: 1
        $x_1_108 = "phid=%s&eb" ascii //weight: 1
        $x_1_109 = "FORM: user: %s, pass: %s" ascii //weight: 1
        $x_2_110 = "phid=%s&eb=FORM: %s;INFO: %s" ascii //weight: 2
        $x_1_111 = "https://signin.ebay*/ws/eBayISAPI.dll" ascii //weight: 1
        $x_2_112 = "user: %s, pass: %s;INFO: %s" ascii //weight: 2
        $x_1_113 = "GetUserDefaultLangID" ascii //weight: 1
        $x_1_114 = "c:\\text.tst" ascii //weight: 1
        $x_1_115 = "c:\\wop.rep" ascii //weight: 1
        $x_1_116 = "c:\\z.www" ascii //weight: 1
        $x_2_117 = "phid=%s&ver=%s&lg=%s" ascii //weight: 2
        $x_1_118 = "11:30:33" ascii //weight: 1
        $x_2_119 = "-bdec=%.2f -hname=%s -new=%s -old=%s -coms=%s" ascii //weight: 2
        $x_1_120 = "c:\\zzzzzzzzzzzzzzzzzzzzzzz" ascii //weight: 1
        $x_2_121 = "f -hname=%s -new=%s -old=%s -coms" ascii //weight: 2
        $x_1_122 = "finanzstatus" ascii //weight: 1
        $x_1_123 = "fund transfer" ascii //weight: 1
        $x_1_124 = "hname=%s -new" ascii //weight: 1
        $x_1_125 = "https://banking" ascii //weight: 1
        $x_2_126 = "s&confirm=%s&sum=%s" ascii //weight: 2
        $x_2_127 = "e input -r name=betrag" ascii //weight: 2
        $x_2_128 = "cccccccoemrciermicomeriocmeiormcioermo" ascii //weight: 2
        $x_2_129 = "; ballance: " ascii //weight: 2
        $x_1_130 = "maxtransfer: " ascii //weight: 1
        $x_2_131 = "phid=%s&sum=%s" ascii //weight: 2
        $x_1_132 = "app/ueberweisung.input" ascii //weight: 1
        $x_1_133 = "postbank.de/app" ascii //weight: 1
        $x_1_134 = "r name=empfaengerBlz" ascii //weight: 1
        $x_1_135 = "r name=empfaengerKontonummer" ascii //weight: 1
        $x_1_136 = "ueberweisung.input.do" ascii //weight: 1
        $x_1_137 = "ueberweisung.prep.do" ascii //weight: 1
        $x_1_138 = "app/kontoumsatz.umsatz.init.do" ascii //weight: 1
        $x_1_139 = "de/app/kontoumsatz.umsatz.init.do" ascii //weight: 1
        $x_1_140 = "de/app/welcome.do" ascii //weight: 1
        $x_1_141 = "name=empfaengerBlz" ascii //weight: 1
        $x_1_142 = "name=empfaengerKontonummer" ascii //weight: 1
        $x_1_143 = "empfaengerKontonummer*empfaengerBlz" ascii //weight: 1
        $x_1_144 = "empfaengerName*empfaengerKontonummer" ascii //weight: 1
        $x_1_145 = "verwendungszweck" ascii //weight: 1
        $x_1_146 = "kontoumsatz.umsatz.init.do" ascii //weight: 1
        $x_1_147 = "postbank.de/app/welcome.do" ascii //weight: 1
        $x_1_148 = "r name=empfaengerName" ascii //weight: 1
        $x_1_149 = "r name=verwendungszweck" ascii //weight: 1
        $x_1_150 = "umsatz.init.do" ascii //weight: 1
        $x_1_151 = "POP3 Password" ascii //weight: 1
        $x_1_152 = "POP3 User" ascii //weight: 1
        $x_1_153 = "ergkoperk gerkgprk gker" ascii //weight: 1
        $x_1_154 = "c;comments" ascii //weight: 1
        $x_1_155 = "h;holdername" ascii //weight: 1
        $x_1_156 = "k;kontonummer" ascii //weight: 1
        $x_2_157 = "<font color=\"#009900\">%.2f&nbsp;</font>" ascii //weight: 2
        $x_1_158 = "app/ueberweisung.quittung.do" ascii //weight: 1
        $x_1_159 = "creatures are desearting" ascii //weight: 1
        $x_1_160 = "Deleted OE Account" ascii //weight: 1
        $x_1_161 = "IE:Password-Protected sites" ascii //weight: 1
        $x_1_162 = "<font color=\"#009900\">%.2f&nbsp;&euro;</font>" ascii //weight: 1
        $x_1_163 = "app/finanzstatus.reduziert" ascii //weight: 1
        $x_1_164 = "span class=\"digit\"> </span" ascii //weight: 1
        $x_1_165 = "jwie0f93j" ascii //weight: 1
        $x_1_166 = "phid=%s&sum=%s&str=%s" ascii //weight: 1
        $x_1_167 = ". fund transfer: " ascii //weight: 1
        $x_1_168 = "*pinNumber*" ascii //weight: 1
        $x_2_169 = "confirm=%s&sum=%s&acc" ascii //weight: 2
        $x_1_170 = "highlighted words" ascii //weight: 1
        $x_2_171 = "conducted in MEGA3. The DNA sequence and other" ascii //weight: 2
        $x_2_172 = {63 6f 6d 70 69 64 00 00 52 54 5f 44 4c}  //weight: 2, accuracy: High
        $x_2_173 = {7a 7a 7a 32 32 32 00 00 00 63 3a 5c 64 6a 72 67}  //weight: 2, accuracy: High
        $x_3_174 = {5b 4b 45 59 4c 4f 47 47 45 52 5d 3a [0-8] 2d 2d 2d 2d 2d 2d 2d 2d}  //weight: 3, accuracy: Low
        $x_2_175 = "\\hook.dll" ascii //weight: 2
        $x_2_176 = "<Esc>" ascii //weight: 2
        $x_2_177 = "<BkSp>" ascii //weight: 2
        $x_2_178 = "__MyKeyLogger" ascii //weight: 2
        $x_3_179 = {53 65 74 48 6f 6f 6b 00 00 00 53 65 74 48 6f 6f}  //weight: 3, accuracy: High
        $x_3_180 = {70 68 70 00 65 78 65 00 5c}  //weight: 3, accuracy: High
        $x_1_181 = "kyrpa" ascii //weight: 1
        $x_2_182 = {0f b7 c7 ff 34 85 40 a0 40 00 56 e8 ?? ?? 00 00 83 c4 0c 85 c0 74 0f 47 66 81 ff 06 01 76 d8}  //weight: 2, accuracy: Low
        $x_2_183 = {83 f8 14 72 2a 80 7f 09 06 75 24 0f b7 4f 02 8b d1 c1 ea 08 c1 e1 08 03 d1 83 fa 28 7e 11 39 ae}  //weight: 2, accuracy: High
        $x_2_184 = {80 f9 19 88 4d ff 73 3c 0f b6 c1 03 c7 8a 04 18 3c 2e 72 1e 3c 7a 77 1a 3c 2f 74 16 3c 39 76 04}  //weight: 2, accuracy: High
        $x_3_185 = {59 3d 27 92 98 00 59 75 08 6a 59}  //weight: 3, accuracy: High
        $x_2_186 = {ff 58 b9 80 01 00 00 89 4d 0c 8b 45 0c 40 40 8d 04 40 c1 e0 07 39 45 0c 75}  //weight: 2, accuracy: High
        $x_2_187 = {8d 45 b4 6a 32 50 ff 15 ?? ?? 40 00 8d 45 e8 89 5d ec 50 8d 45 ec 50 53 68 3f 00 0f 00 53 53 53}  //weight: 2, accuracy: Low
        $n_100_188 = {68 74 74 70 [0-1] 3a 2f 2f 77 77 77 2e 67 74 6f 70 61 6c 61 2e 63 6f 6d 2f}  //weight: -100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((13 of ($x_1_*))) or
            ((1 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_2_*) and 5 of ($x_1_*))) or
            ((5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((7 of ($x_2_*))) or
            ((1 of ($x_3_*) and 10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((3 of ($x_3_*) and 4 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((4 of ($x_3_*) and 1 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((5 of ($x_3_*))) or
            ((1 of ($x_5_*) and 8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Cimuz_B_2147806853_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Cimuz.B"
        threat_id = "2147806853"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Cimuz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {be 00 d0 00 00 2d d8 d0 00 00 56 89 45 f0 89 5d f4 89 5d f8}  //weight: 1, accuracy: High
        $x_1_2 = {8d 34 01 8a c1 f6 ea 30 06 41 3b 4d 08 72 ec ff 75 fc}  //weight: 1, accuracy: High
        $x_1_3 = {74 3a 8b 7e 20 8b 5e 24 03 f9 03 d9 3b c2 89 55 08 76 29}  //weight: 1, accuracy: High
        $x_1_4 = {8d 59 24 8b 33 8b 3b 8b ce c1 e9 1d c1 ee 1e 83 e1 01 83 e6 01 c1 ef 1f f6 43 03 02 74 13}  //weight: 1, accuracy: High
        $x_1_5 = {0f b7 0a 8b d9 66 81 e3 00 f0 81 fb 00 30 00 00}  //weight: 1, accuracy: High
        $n_5_6 = ".vividas.com" ascii //weight: -5
        $n_5_7 = "OCXPLAY.VPlayerPropPage.1" ascii //weight: -5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

rule PWS_Win32_Cimuz_A_2147806864_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Cimuz.gen.dll!A"
        threat_id = "2147806864"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Cimuz"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {68 6f 6f 6b 2e 64 6c 6c 00 53 65 74 48 6f 6f 6b 00 55 6e 53 65 74 48 6f 6f 6b}  //weight: 5, accuracy: High
        $x_1_2 = {6a 01 58 39 44 24 08 75 0a 8b 4c 24 04 89}  //weight: 1, accuracy: High
        $x_1_3 = {81 7e 04 02 01 00 00 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Cimuz_D_2147806866_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Cimuz.D"
        threat_id = "2147806866"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Cimuz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 04 24 8b 54 24 04 8a 44 10 ff 8a 54 1d ff 32 c2 88 07 47 43 8b c5}  //weight: 4, accuracy: High
        $x_1_2 = {8b 45 fc 8b 40 3c 03 45 fc 89 45 e8 8b 45 fc e8}  //weight: 1, accuracy: High
        $x_1_3 = {53 56 57 55 8b f9 8b ea 8b f0 b8 34 14 14 13 3b 05}  //weight: 1, accuracy: High
        $x_1_4 = "GetWindowsDirectoryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

