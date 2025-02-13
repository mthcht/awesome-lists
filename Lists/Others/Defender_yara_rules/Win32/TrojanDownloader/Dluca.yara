rule TrojanDownloader_Win32_Dluca_BF_2147575183_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dluca.BF"
        threat_id = "2147575183"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dluca"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Apwheel" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "Control Panel\\International" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Internet Explorer" ascii //weight: 1
        $x_1_5 = "\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_6 = "/ok.txt" ascii //weight: 1
        $x_1_7 = "&hf=" ascii //weight: 1
        $x_1_8 = "&affid=" ascii //weight: 1
        $x_1_9 = "&cc=" ascii //weight: 1
        $x_1_10 = "CS4N3a6tionSCode" ascii //weight: 1
        $x_1_11 = "Software\\Ceres" ascii //weight: 1
        $x_1_12 = "&is=0" ascii //weight: 1
        $x_1_13 = "&is=1" ascii //weight: 1
        $x_1_14 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\{00" ascii //weight: 1
        $x_1_15 = "&hc2=" ascii //weight: 1
        $x_1_16 = "&hc1=" ascii //weight: 1
        $x_1_17 = "/bho/report.asp?g=" ascii //weight: 1
        $x_1_18 = "Software\\commok" ascii //weight: 1
        $x_1_19 = ".abetterinternet.com" ascii //weight: 1
        $x_1_20 = "xplore2_exe" ascii //weight: 1
        $x_1_21 = "CHANGESERVER" ascii //weight: 1
        $x_1_22 = "POPUP" ascii //weight: 1
        $x_1_23 = "SHORTCUT" ascii //weight: 1
        $x_1_24 = "config.txt" ascii //weight: 1
        $x_1_25 = "&ri=1" ascii //weight: 1
        $x_1_26 = "configpath" ascii //weight: 1
        $x_1_27 = "bho/config.asp?g=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (22 of ($x*))
}

rule TrojanDownloader_Win32_Dluca_DJ_2147595096_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dluca.DJ"
        threat_id = "2147595096"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dluca"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CHAT,http://freechattalk.com/info/sms" ascii //weight: 1
        $x_1_2 = "SMS,http://freechattalk.com/info/sms" ascii //weight: 1
        $x_1_3 = "C:\\Program Files\\Common Files\\System\\%s.exe" ascii //weight: 1
        $x_1_4 = "http://w.hqwmdjejtudlk-dfjkeid.com/" wide //weight: 1
        $x_1_5 = "-kill %s %s /install" ascii //weight: 1
        $x_1_6 = "Freechatroomchat.com" ascii //weight: 1
        $x_1_7 = "wpa.asdfjkluiop.com" ascii //weight: 1
        $x_1_8 = "c:\\temp\\noname.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dluca_AN_2147601483_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dluca.AN"
        threat_id = "2147601483"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dluca"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "qdelwbi.tmp" ascii //weight: 1
        $x_1_2 = "AOL Frame25" ascii //weight: 1
        $x_1_3 = "_IE_Hook_Wnd_" ascii //weight: 1
        $x_1_4 = "\\%s_update.exe" ascii //weight: 1
        $x_1_5 = "\\dialers" ascii //weight: 1
        $x_1_6 = "c:\\SSUpdate.exe" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_8 = "-kill %s %s /install" ascii //weight: 1
        $x_1_9 = "%s\\SafeSearch.dll" ascii //weight: 1
        $x_1_10 = "Software\\Microsoft\\Windows\\Currentversion\\Uninstall\\SafeSearch" ascii //weight: 1
        $x_1_11 = "c:\\program files\\primesoft\\safesearch\\safesearch.exe" ascii //weight: 1
        $x_1_12 = "http://204.177.92.207/safesearch/index.php?srch=%s&pin=%s&ccinfo=%s" ascii //weight: 1
        $x_1_13 = "216.177.73.139" ascii //weight: 1
        $x_1_14 = "http://204.177.92.191/" ascii //weight: 1
        $x_1_15 = "http://sitefinder.verisign.com/" ascii //weight: 1
        $x_1_16 = "eps.new.search.new.net/apps/eps" ascii //weight: 1
        $x_1_17 = "www.commonname.com/en/powersearch" ascii //weight: 1
        $x_1_18 = "aolsearch.aol.com" ascii //weight: 1
        $x_1_19 = "hot.aol.com" ascii //weight: 1
        $x_1_20 = "www.searchresult.net" ascii //weight: 1
        $x_1_21 = "ieautosearch" ascii //weight: 1
        $x_1_22 = "ad.doubleclick.net" ascii //weight: 1
        $x_1_23 = "www.ignkeywords.com" ascii //weight: 1
        $x_1_24 = "auto.search.msn.com" ascii //weight: 1
        $x_1_25 = "qsearch://titlefilter?" ascii //weight: 1
        $x_1_26 = "http://msdvm.com/" ascii //weight: 1
        $x_1_27 = {8b 46 04 8b ce 50 e8 ?? ?? 00 00 66 85 c0 74 2d 8b 0d ?? ?? 41 00 8b 56 04 51 52 55 55 55 55 68 00 7d 00 00 68 00 7d 00 00 55 53 68 ?? ?? 41 00 55 ff 15 ?? ?? 41 00 89 86 08 03 00 00 8b 86 08 03 00 00 3b c5 74 0b 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dluca_AO_2147604882_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dluca.AO"
        threat_id = "2147604882"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dluca"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "CFDATA.ima?ccode=%s&cfdatacc=%s&gmt=%d" ascii //weight: 5
        $x_5_2 = "&ivh=%d&dvh=%d&ivl=%d&dvl=%d&id=%s" ascii //weight: 5
        $x_5_3 = "%swk/getclientid.wnk?srv=%s&ver=%s" ascii //weight: 5
        $x_5_4 = "%swk/getclientinfo.wnk?id=%s&srv=%s&ver=%s&docid=%s&time=%d&cstate=%d&state=%s&flash=%s" ascii //weight: 5
        $x_5_5 = "cpv.jsp?p=110956&response=xml&url=%s&context=%s&ron=off" ascii //weight: 5
        $x_1_6 = "%s%s@adtrgt.com/" ascii //weight: 1
        $x_1_7 = "%s%s@popunder.adtrgt.com/" ascii //weight: 1
        $x_1_8 = "%s%s@url.adtrgt.com/" ascii //weight: 1
        $x_1_9 = "%s:Zone.Identifier" ascii //weight: 1
        $x_1_10 = "%s\\system\\%s.exe" ascii //weight: 1
        $x_1_11 = "%s~cfdata.txt" ascii //weight: 1
        $x_1_12 = "%195.8.15.138" ascii //weight: 1
        $x_1_13 = "217.145.76.13" ascii //weight: 1
        $x_1_14 = "%aolsearch.aol.com" ascii //weight: 1
        $x_1_15 = "cnet.com" ascii //weight: 1
        $x_1_16 = "freepornnow.net" ascii //weight: 1
        $x_1_17 = "freeporntoday.net" ascii //weight: 1
        $x_1_18 = "kjdhendieldiouyu.com" ascii //weight: 1
        $x_1_19 = "myspace.com" ascii //weight: 1
        $x_1_20 = "porn1.org" ascii //weight: 1
        $x_1_21 = "sea.search.msn.com" ascii //weight: 1
        $x_1_22 = "search.aol.com" ascii //weight: 1
        $x_1_23 = "search.live.com" ascii //weight: 1
        $x_1_24 = "search.lycos.com" ascii //weight: 1
        $x_1_25 = "search.msn.com" ascii //weight: 1
        $x_1_26 = "search.netscape.com" ascii //weight: 1
        $x_1_27 = "search.yahoo.com" ascii //weight: 1
        $x_1_28 = "sweepstakess.com" ascii //weight: 1
        $x_1_29 = "virgins.gr" ascii //weight: 1
        $x_1_30 = "virgins.lt" ascii //weight: 1
        $x_1_31 = "virgins.se" ascii //weight: 1
        $x_1_32 = "www.altavista.com" ascii //weight: 1
        $x_1_33 = "www.google." ascii //weight: 1
        $x_1_34 = "www.live.com" ascii //weight: 1
        $x_1_35 = "www.search.com" ascii //weight: 1
        $x_1_36 = "www.yahoo.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((20 of ($x_1_*))) or
            ((1 of ($x_5_*) and 15 of ($x_1_*))) or
            ((2 of ($x_5_*) and 10 of ($x_1_*))) or
            ((3 of ($x_5_*) and 5 of ($x_1_*))) or
            ((4 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Dluca_DM_2147605467_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dluca.DM"
        threat_id = "2147605467"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dluca"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {85 c0 74 21 8d 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 57 50 e8 ?? ?? ?? ?? 83 c4 10 80 a5 ?? ?? ?? ?? 00 6a 3f 59 33 c0 8d bd ?? ?? ?? ?? f3 ab 66 ab aa 8d 85 ?? ?? ?? ?? 8b ce 50}  //weight: 2, accuracy: Low
        $x_3_2 = "204.177.92.191" ascii //weight: 3
        $x_3_3 = "vmx38Fg45" ascii //weight: 3
        $x_1_4 = "msdvm.exe" ascii //weight: 1
        $x_1_5 = "%sw/getclientid?srv=%s&ver=%s" ascii //weight: 1
        $x_1_6 = "%sw/getclientinfo?id=%s&srv=%s&ver=%s&docid=%s&time=%d&cstate=%d&state=%s&flash=%s" ascii //weight: 1
        $x_1_7 = "%s?nm=%s&rc=%d" ascii //weight: 1
        $x_1_8 = "c:\\msdvm%2.0d" ascii //weight: 1
        $x_1_9 = "Click Me" ascii //weight: 1
        $x_1_10 = "ad.doubleclick.net/adi/sp.3236/;kw=" ascii //weight: 1
        $x_1_11 = "216.177.73.139" ascii //weight: 1
        $x_1_12 = "popup=" ascii //weight: 1
        $x_1_13 = "&pin=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

