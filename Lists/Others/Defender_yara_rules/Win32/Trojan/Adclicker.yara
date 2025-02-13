rule Trojan_Win32_Adclicker_AH_2147596376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adclicker.AH"
        threat_id = "2147596376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adclicker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "googleasq,google.,as_q=," ascii //weight: 1
        $x_1_2 = "yahoo,yahoo.,p=," ascii //weight: 1
        $x_1_3 = "yahoo_atavista,yahoo.,q=," ascii //weight: 1
        $x_1_4 = "msn,msn.,q=," ascii //weight: 1
        $x_1_5 = "baidu,baidu.com,wd=," ascii //weight: 1
        $x_1_6 = "dmoz,dmoz.,search=," ascii //weight: 1
        $x_1_7 = "netscape,netscape.com,s=," ascii //weight: 1
        $x_1_8 = "about,about.com,terms=," ascii //weight: 1
        $x_1_9 = "looksmart,looksmart.com,qt=," ascii //weight: 1
        $x_1_10 = "ntlworld,ntlworld.,q=," ascii //weight: 1
        $x_1_11 = "earthlink,earthlink.,q=," ascii //weight: 1
        $x_1_12 = "mywebsearch,mywebsearch.,searchfor=," ascii //weight: 1
        $x_1_13 = "live,live.com,q=," ascii //weight: 1
        $x_1_14 = "alexa,alexa.com,q=," ascii //weight: 1
        $x_1_15 = "jayde,jayde.,query=," ascii //weight: 1
        $x_1_16 = "dogpile,dogpile.com,web/,/" ascii //weight: 1
        $x_1_17 = "libero,libero.it,query=," ascii //weight: 1
        $x_1_18 = "webde,web.de,su=," ascii //weight: 1
        $x_1_19 = "comcast,comcast.net,q=," ascii //weight: 1
        $x_1_20 = "youtube,youtube.com,search_query=," ascii //weight: 1
        $x_1_21 = "seznam,seznam.cz,w=," ascii //weight: 1
        $x_1_22 = "overture,overture.com,Keywords=," ascii //weight: 1
        $x_1_23 = "bloggerq,search.blogger.com,as_q=," ascii //weight: 1
        $x_1_24 = "cnn,cnn.com,query=," ascii //weight: 1
        $x_1_25 = "terra,terra.com.br,query=," ascii //weight: 1
        $x_1_26 = "bbc,bbc.co.uk,q=," ascii //weight: 1
        $x_1_27 = {83 c4 f8 c7 04 24 3c 00 00 00 bb 78 15 42 00 8b 35 c4 16 42 00 8b 3d b8 16 42 00 8b 2d 44 17 42 00 a1 d0 16 42 00 89 44 24 04 83 3b 00 74 1e 55 8b 44 24 08 50 8b cf 8b d6 8b 03 e8 50 fe ff ff a1 1c 17 42 00 c7 00 3c 00 00 00 eb 1e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adclicker_AI_2147596611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adclicker.AI"
        threat_id = "2147596611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adclicker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\system32\\home.htm" ascii //weight: 1
        $x_1_2 = "%s\\yahoo.htm" ascii //weight: 1
        $x_1_3 = "%s\\google.htm" ascii //weight: 1
        $x_1_4 = "%s\\msn.htm" ascii //weight: 1
        $x_1_5 = "%s\\sec.htm" ascii //weight: 1
        $x_1_6 = "'Browser Helper Objects'" ascii //weight: 1
        $x_1_7 = "BhoNew.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adclicker_AK_2147596741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adclicker.AK"
        threat_id = "2147596741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adclicker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "305"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "InternetCrackUrlA" ascii //weight: 100
        $x_100_2 = "202.67.220.219/trafc-2/rfe.php" ascii //weight: 100
        $x_100_3 = "1DAEFCB9-06C8-47c6-8F20-3FB54B244DAA" ascii //weight: 100
        $x_1_4 = "search.about.com" ascii //weight: 1
        $x_1_5 = "search.aol.co" ascii //weight: 1
        $x_1_6 = "search.asiaco.com" ascii //weight: 1
        $x_1_7 = "search.daum.net" ascii //weight: 1
        $x_1_8 = "search.dmoz.org" ascii //weight: 1
        $x_1_9 = "search.earthlink.net" ascii //weight: 1
        $x_1_10 = "search.gohip.com" ascii //weight: 1
        $x_1_11 = "search.looksmart.com" ascii //weight: 1
        $x_1_12 = "search.lycos.co.uk" ascii //weight: 1
        $x_1_13 = "search.lycos.com" ascii //weight: 1
        $x_1_14 = "search.msn.co" ascii //weight: 1
        $x_1_15 = "search.msn.fr" ascii //weight: 1
        $x_1_16 = "search.netscape.com" ascii //weight: 1
        $x_1_17 = "search.netzero.net" ascii //weight: 1
        $x_1_18 = "search.sympatico.msn.ca" ascii //weight: 1
        $x_1_19 = "search.wanadoo.co.uk" ascii //weight: 1
        $x_1_20 = "search.xtramsn.co.nz" ascii //weight: 1
        $x_1_21 = "search.yahoo.co" ascii //weight: 1
        $x_1_22 = "searchfeed.com" ascii //weight: 1
        $x_1_23 = "searchmiracle.com" ascii //weight: 1
        $x_1_24 = "searchscout.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Adclicker_AL_2147596935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adclicker.AL"
        threat_id = "2147596935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adclicker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Vrail" wide //weight: 1
        $x_1_2 = "shdoclc.dll/navcancl.htm#" wide //weight: 1
        $x_1_3 = "url.cpvfeed.com" wide //weight: 1
        $x_1_4 = "#update_shoppingsites" wide //weight: 1
        $x_1_5 = "#pushlist_update" wide //weight: 1
        $x_1_6 = "aupd.exe" wide //weight: 1
        $x_1_7 = "counter_shopping_popup" wide //weight: 1
        $x_1_8 = "next_shopping_time" wide //weight: 1
        $x_1_9 = "shopping_pop_interval" wide //weight: 1
        $x_1_10 = "max_shopping_pop" wide //weight: 1
        $x_1_11 = "shopping_sites" wide //weight: 1
        $x_1_12 = "shopping_popups_enabled" wide //weight: 1
        $x_1_13 = "HTML Exploits Prevent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adclicker_AJ_2147596938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adclicker.AJ"
        threat_id = "2147596938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adclicker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "75"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "86A44EF7-78FC-4e18-A564-B18F806F7F56" ascii //weight: 50
        $x_10_2 = "InternetReadFile" ascii //weight: 10
        $x_10_3 = "InternetConnectA" ascii //weight: 10
        $x_1_4 = "my.begun.ru" ascii //weight: 1
        $x_1_5 = "google.com/adsense/" ascii //weight: 1
        $x_1_6 = "promoforum.ru" ascii //weight: 1
        $x_1_7 = "seochase.com" ascii //weight: 1
        $x_1_8 = "mastertalk.ru" ascii //weight: 1
        $x_1_9 = "forum.searchengines.ru" ascii //weight: 1
        $x_1_10 = "searchengines.ru" ascii //weight: 1
        $x_1_11 = "armadaboard.com" ascii //weight: 1
        $x_1_12 = "umaxforum.com" ascii //weight: 1
        $x_1_13 = "crutop.nu" ascii //weight: 1
        $x_1_14 = "crutop.com" ascii //weight: 1
        $x_1_15 = "master-x.com" ascii //weight: 1
        $x_1_16 = "umaxlogin.com" ascii //weight: 1
        $x_1_17 = "rusawm.com" ascii //weight: 1
        $x_1_18 = "gofuckyourself.com" ascii //weight: 1
        $x_1_19 = "oprano.com" ascii //weight: 1
        $x_1_20 = "gfyboard.com" ascii //weight: 1
        $x_1_21 = "gfy.com" ascii //weight: 1
        $x_1_22 = "adultwebmasterinfo.com" ascii //weight: 1
        $x_1_23 = "xbiz.com" ascii //weight: 1
        $x_1_24 = "boards.xbiz.com" ascii //weight: 1
        $x_1_25 = "nastraforum.com" ascii //weight: 1
        $x_1_26 = "webhostingtalk.com" ascii //weight: 1
        $x_1_27 = "searchengineforums.com" ascii //weight: 1
        $x_1_28 = "benedelman.org" ascii //weight: 1
        $x_1_29 = "webmasterworld.com" ascii //weight: 1
        $x_1_30 = "askdamage.com" ascii //weight: 1
        $x_1_31 = "namepros.com" ascii //weight: 1
        $x_1_32 = "castlecops.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 25 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_10_*) and 15 of ($x_1_*))) or
            ((1 of ($x_50_*) and 2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Adclicker_AN_2147597963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adclicker.AN"
        threat_id = "2147597963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adclicker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "145"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "VBA6.DLL" ascii //weight: 20
        $x_20_2 = "&query=" wide //weight: 20
        $x_20_3 = "&keyword=" wide //weight: 20
        $x_20_4 = "E:\\be kin to\\S" wide //weight: 20
        $x_20_5 = "Daum Watch\\HitControl.vbp" wide //weight: 20
        $x_20_6 = "InternetOpenUrlA" ascii //weight: 20
        $x_20_7 = "InternetReadFile" ascii //weight: 20
        $x_1_8 = "naver.com" wide //weight: 1
        $x_1_9 = "yahoo.com" wide //weight: 1
        $x_1_10 = "empas.com" wide //weight: 1
        $x_1_11 = "dreamwiz.com" wide //weight: 1
        $x_1_12 = "nate.com" wide //weight: 1
        $x_1_13 = "hanafos.com" wide //weight: 1
        $x_1_14 = "msn.co.kr" wide //weight: 1
        $x_1_15 = "freechal.com" wide //weight: 1
        $x_1_16 = "paran.com" wide //weight: 1
        $x_1_17 = "google.co.kr" wide //weight: 1
        $x_1_18 = "live.com" wide //weight: 1
        $x_1_19 = "esnaper.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_20_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Adclicker_AO_2147598340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adclicker.AO"
        threat_id = "2147598340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adclicker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".php?id=" ascii //weight: 2
        $x_1_2 = "Panel\\International\\Geo" ascii //weight: 1
        $x_1_3 = "clickreferer" ascii //weight: 1
        $x_1_4 = "class=title" ascii //weight: 1
        $x_1_5 = "HookWWW" ascii //weight: 1
        $x_1_6 = "DllGetClassObject" ascii //weight: 1
        $x_4_7 = {70 6f 70 75 72 6c 00 00 70 6f 70 00 6c 61 62 65 6c 00}  //weight: 4, accuracy: High
        $x_2_8 = {5b 6b 65 79 77 6f 72 64 5d 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Adclicker_AQ_2147601004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adclicker.AQ"
        threat_id = "2147601004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adclicker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 45 f4 83 7d f4 ff 0f 95 45 fb 80 7d fb 00 74 09 8b 45 f4 50}  //weight: 5, accuracy: High
        $x_5_2 = {64 89 20 c7 45 e8 04 00 00 00 c7 45 e4 04 00 00 00 8d 45 e4 50 8d 45 f0 50 8d 45 e8 50 6a 00 8b 45 f4}  //weight: 5, accuracy: High
        $x_2_3 = "is webmaster's" ascii //weight: 2
        $x_2_4 = "gofuckyourself.com" ascii //weight: 2
        $x_2_5 = "Explorer\\Titles" ascii //weight: 2
        $x_2_6 = "%SYSTEM%\\dllcache\\IExplore.exe" ascii //weight: 2
        $x_2_7 = "No settings dir" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Adclicker_AR_2147603092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adclicker.AR"
        threat_id = "2147603092"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adclicker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "127.0.0.1  www1.tmdqq.net" ascii //weight: 1
        $x_1_2 = "Del.bat" ascii //weight: 1
        $x_1_3 = "del \"c:\\new.exe\"" ascii //weight: 1
        $x_1_4 = "127.0.0.1  www3.57185.com" ascii //weight: 1
        $x_1_5 = {8b c8 49 ba 01 00 00 00 a1 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 55 e8 b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ff ff eb 0f b8 ?? ?? ?? ?? ba ?? ?? ?? ?? e8 ?? ?? ff ff b8 ?? ?? ?? ?? ba ?? ?? ?? ?? e8 ?? ?? ff ff 8d 45 e4 e8 ?? ?? ff ff 8b 55 e4 b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ff ff e8 ?? ?? ff ff e8 ?? ?? ff ff 6a 00 b9 ?? ?? ?? ?? b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ff ff 68 10 27 00 00 e8 ?? ?? ff ff e8 ?? ?? ff ff b8 02 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adclicker_AS_2147603405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adclicker.AS"
        threat_id = "2147603405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adclicker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 65 73 74 ?? ?? ?? ?? ?? ?? 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_2 = "Agent%ld" ascii //weight: 1
        $x_1_3 = {55 8b ec 83 ec ?? 53 56 33 f6 57 8d 45 ?? 56 8b f9 50 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 6a 40 8d 45 ?? 56 50 e8 ?? ?? ?? ?? 83 c4 0c ff 15 ?? ?? ?? ?? 50 8d 45 ?? 68 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 83 c4 0c f6 45 ?? ?? 56 56 56 75 04 6a 04 eb 01 56 8d 45 ?? 50}  //weight: 1, accuracy: Low
        $x_1_4 = {33 db eb 76 8b 06 6a 02 6a 00 8b ce ff 50 30 ff 75 f0 8b 06 8d 8d e0 fe ff ff 51 8b ce ff 50 40 8b 06 6a 01 68 ?? ?? ?? ?? 8b ce ff 50 40 8b 07 6a 02 6a 00 8b cf ff 50 30 ff 75 f0 8b 07 8d 8d e0 fe ff ff 51 8b cf ff 50 40 8b 07 6a 01 68 ?? ?? ?? ?? 8b cf ff 50 40 6a 05 6a 00 8d 85 e0 fe ff ff 6a 00 50 8b cb e8 ?? ?? ?? ?? 50 6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a 01 5b 8d 4d e0}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 01 58 89 83 ?? ?? ?? ?? 8b d8 e9 1b 01 00 00 8d 83 ?? ?? ?? ?? 50 8d 85 e0 fd ff ff 50 e8 ?? ?? ?? ?? 8d 85 e0 fe ff ff 50 8d 85 e0 fd ff ff 50 e8 ?? ?? ?? ?? 83 c4 10 8b cb 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 8d 85 e0 fe ff ff 50 e8 ?? ?? ?? ?? 59 59 68 ?? ?? ?? ?? 8b cb e8 ?? ?? ?? ?? 50 8d 85 e0 fd ff ff 50 e8 ?? ?? ?? ?? 59 8d 83 ?? ?? ?? ?? 59 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adclicker_AU_2147603586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adclicker.AU"
        threat_id = "2147603586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adclicker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/reg.php?" ascii //weight: 1
        $x_1_2 = "popup\\release\\popup.pdb" ascii //weight: 1
        $x_1_3 = "svchost.exe" ascii //weight: 1
        $x_1_4 = {b8 64 20 00 00 e8 46 fe ff ff a1 ?? ?? ?? ?? 33 c4 89 84 24 5c 20 00 00 68 00 10 00 00 8d 44 24 5c 6a 00 50 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 4c 24 68 68 00 10 00 00 51 e8 ?? ?? ?? ?? 83 c4 18 68 00 10 00 00 8d 94 24 5c 10 00 00 52 8d 44 24 60 50 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 8c 24 5c 10 00 00 51 68 ?? ?? ?? ?? 8d 54 24 64 68 00 10 00 00 52 e8 ?? ?? ?? ?? 6a 44 8d 44 24 28 6a 00 50 e8 ?? ?? ?? ?? 83 c4 20 8d 0c 24 51 8d 54 24 14 52 6a 00 6a 00 6a 20}  //weight: 1, accuracy: Low
        $x_1_5 = {33 c0 50 50 6a 03 50 6a 03 68 00 00 00 40 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? c3 a1 ?? ?? ?? ?? 83 f8 ff 56 8b 35 ?? ?? ?? ?? 74 08 83 f8 fe 74 03 50 ff d6 a1 ?? ?? ?? ?? 83 f8 ff 74 08 83 f8 fe 74 03 50 ff d6 5e c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adclicker_KR_2147605412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adclicker.KR"
        threat_id = "2147605412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adclicker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "38"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {19 61 62 6f 75 74 3a 62 6c 61 6e 6b 00 71 75 65 72 79 49 6e 66 6f 00 00 00 2e 6c 6f 74 74 65 73 68 6f 70 70 69 6e 67 2e 00 71 00 00 00 2e 6d 6d 2e 00 00 00 00 70 72 65 5f 71 72 79 00 2e 62 62 2e 00 00 00 00 6f 72 67 6b 65 79 77 6f 72 64 00 00 2e 65 6e 75 72 69 2e 00 6b 31 00 00 2e 64 61 6e 61 77 61 2e 00 00 00 00 2e 67 73 65 73 74 6f 72 65 2e 00 00 6b 77 64 00 2e 6d 70 6c 65 2e 00 00 73 65 61 72 63 68 5f 73 74 72 00 00 2e 64 64 6d 2e 00 00 00 73 4b 65 79 57 6f 72 64 00 00 00 00 2e 79 65 6f 69 6e 2e 00 2e 6e 73 65 73 68 6f 70 2e 00 00 00 73 63 68 5f 77 6f 72 64 00 00 00 00 2e 7a 65 72 6f 6d 61 72 6b 65 74 2e 00 00 00 00 71 75 65 72 79 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {2e 6c 6f 74 74 65 2e 00 73 65 61 72 63 68 54 65 72 6d 00 00 2f 6d 61 69 6e 2f 6d 61 6c 6c 6d 61 69 6e 2e 64 6f 00 00 00 2e 73 68 69 6e 73 65 67 61 65 2e 00 2f 69 6e 64 65 78 2e 67 73 00 00 00 2e 67 73 65 73 68 6f 70 2e 00 00 00 71 75 65 72 79 31 00 00 2f 69 6e 64 65 78 5f 74 61 62 31 2e 6a 73 70 00 2e 63 6a 6d 61 6c 6c 2e 00 00 00 00 53 45 41 52 43 48 5f 4b 45 59 57 4f 52 44 00 00 2f 3f 53 69 64 3d 42 42 42 42 5f 4e 53 30 30 30 30 30 30 5f 30 30 5f 30 30 00}  //weight: 10, accuracy: High
        $x_10_3 = {2f 3f 53 69 64 3d 41 41 41 41 5f 30 30 30 30 30 30 30 30 5f 30 30 5f 30 30 00 00 00 2f 3f 53 69 64 3d 30 30 30 32 5f 30 31 30 31 30 34 30 30 5f 30 31 5f 30 31 00 00 00 64 6e 73 68 6f 70 2e 00 74 71 00 00 2f 6d 61 6c 6c 73 2f 69 6e 64 65 78 2e 68 74 6d 6c 00 00 00 2e 69 6e 74 65 72 70 61 72 6b 2e 00 67 64 6c 63 43 64 00 00 2f 69 6e 64 65 78 2e 61 73 70 00 00 2f 00 00 00 2e 67 6d 61 72 6b 65 74 2e 00 00 00 2e 61 75 63 74 69 6f 6e 2e 00 00 00 69 73 68 6f 70 00 00}  //weight: 10, accuracy: High
        $x_3_4 = {00 73 65 61 72 63 68 66 75 6e 2e 63 6f 2e 6b 72 2f 61 6e 74 5f 72 65 73 75 6c 74 2e 61 73 70 00 00 73 65 61 72 63 68 2e 69 63 72 6f 73 73 2e 63 6f 2e 6b 72 00}  //weight: 3, accuracy: High
        $x_3_5 = {68 74 74 70 3a 2f 2f 69 74 68 69 6e 6b 2e 74 68 69 6e 6b 73 69 74 65 2e 6b 72 2f 73 65 61 72 63 68 2e 61 73 70 3f 6b 3d 25 73 26 69 64 3d 25 73 00 00}  //weight: 3, accuracy: High
        $x_1_6 = "{E74BC74F-F470-4AD7-9FB4-1A4170A06082}" ascii //weight: 1
        $x_1_7 = "find.pdbox.co.kr:8009" ascii //weight: 1
        $x_1_8 = "{40ABC58A-2603-4EE2-B0ED-B0FA2D115514}" ascii //weight: 1
        $x_1_9 = "{C9564986-6FCD-4A88-A3FE-BB9BE9C0F166}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Adclicker_A_2147609043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adclicker.A"
        threat_id = "2147609043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adclicker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "/cpa/ads?" ascii //weight: 4
        $x_4_2 = ".cn/ads/ads.asp?" ascii //weight: 4
        $x_4_3 = "_0ads_al" ascii //weight: 4
        $x_4_4 = "&ad_type=" ascii //weight: 4
        $x_4_5 = "seo=" ascii //weight: 4
        $x_5_6 = "micr0s0ft.com" ascii //weight: 5
        $x_5_7 = "joyo.com/default.asp?source=ad4all" ascii //weight: 5
        $x_5_8 = "feigou.ini" ascii //weight: 5
        $x_1_9 = {63 6c 69 65 6e 74 3d 63 61 2d 70 75 62 2d 0c 00}  //weight: 1, accuracy: Low
        $x_1_10 = "cpro.baidu.com" ascii //weight: 1
        $x_1_11 = "asiafind.com" ascii //weight: 1
        $x_1_12 = "fuck.asp" ascii //weight: 1
        $x_1_13 = "adclient.china.com" ascii //weight: 1
        $x_1_14 = "ads.china.com" ascii //weight: 1
        $x_1_15 = "ad.tom.com" ascii //weight: 1
        $x_1_16 = {61 64 73 76 69 65 77 ?? 2e 71 71 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_17 = "ads.adbrite.com" ascii //weight: 1
        $x_1_18 = "ad.yigao.com" ascii //weight: 1
        $x_1_19 = "ads8.com" ascii //weight: 1
        $x_1_20 = "mokaads.linkad.cn" ascii //weight: 1
        $x_1_21 = "adsunion.com" ascii //weight: 1
        $x_3_22 = "Referer: http://www.xxx.com" ascii //weight: 3
        $x_3_23 = "Referer: http://www.51626.net" ascii //weight: 3
        $x_3_24 = "Referer: http://tg.sdo.com" ascii //weight: 3
        $x_3_25 = "Referer: http://www.netxboy.com" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 3 of ($x_3_*) and 13 of ($x_1_*))) or
            ((2 of ($x_4_*) and 4 of ($x_3_*) and 10 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_3_*) and 12 of ($x_1_*))) or
            ((3 of ($x_4_*) and 3 of ($x_3_*) and 9 of ($x_1_*))) or
            ((3 of ($x_4_*) and 4 of ($x_3_*) and 6 of ($x_1_*))) or
            ((4 of ($x_4_*) and 1 of ($x_3_*) and 11 of ($x_1_*))) or
            ((4 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_1_*))) or
            ((4 of ($x_4_*) and 3 of ($x_3_*) and 5 of ($x_1_*))) or
            ((4 of ($x_4_*) and 4 of ($x_3_*) and 2 of ($x_1_*))) or
            ((5 of ($x_4_*) and 10 of ($x_1_*))) or
            ((5 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((5 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((5 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((5 of ($x_4_*) and 4 of ($x_3_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*) and 13 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 12 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 11 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_3_*) and 8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 4 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 13 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*) and 10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 4 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_4_*) and 9 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_5_*) and 5 of ($x_4_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 11 of ($x_1_*))) or
            ((2 of ($x_5_*) and 4 of ($x_3_*) and 8 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 13 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 10 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 12 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 9 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 4 of ($x_3_*))) or
            ((2 of ($x_5_*) and 3 of ($x_4_*) and 8 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_4_*) and 3 of ($x_3_*))) or
            ((2 of ($x_5_*) and 4 of ($x_4_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 4 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 4 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*) and 5 of ($x_4_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_1_*))) or
            ((3 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 11 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_3_*))) or
            ((3 of ($x_5_*) and 2 of ($x_4_*) and 7 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_3_*))) or
            ((3 of ($x_5_*) and 3 of ($x_4_*) and 3 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*))) or
            ((3 of ($x_5_*) and 4 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Adclicker_H_2147617072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adclicker.H"
        threat_id = "2147617072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adclicker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {64 61 74 65 00 00 00 00 32 30 30 37 30 31 30 31}  //weight: 10, accuracy: High
        $x_10_2 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; pcagent" ascii //weight: 10
        $x_10_3 = "\\Downloaded Program Files\\desktop.ini" ascii //weight: 10
        $x_1_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e [0-15] 2e (6e|63) 2f 6e 6f 74 65 70 61 64 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {49 45 48 65 6c 70 65 72 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_6 = {63 68 75 6e 6b 65 64 00 49 45 46 72 61 6d 65 00 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72}  //weight: 1, accuracy: High
        $x_1_7 = "report.php?type=click&taskid=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Adclicker_N_2147620394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adclicker.N"
        threat_id = "2147620394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adclicker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 6f 76 65 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_2 = "2D0D6F04-EF5C-4A52-AA29-A146A6466A9C" wide //weight: 1
        $x_1_3 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 [0-4] 6e 00 61 00 6d 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "NdrDllCanUnloadNow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adclicker_O_2147625934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adclicker.O"
        threat_id = "2147625934"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adclicker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HEREISBOOTCODE" ascii //weight: 1
        $x_1_2 = {47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 41 00 90 00 00 77 73 70 72 69 6e 74 66 41 00 00 00 52 65 67 43 6c 6f 73 65 4b 65 79}  //weight: 1, accuracy: High
        $x_1_3 = {56 87 1b 2e 00 00 00 00 ff ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adclicker_KX_2147631751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adclicker.gen!KX"
        threat_id = "2147631751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adclicker"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://banner.auction.co.kr/bn_redirect.asp?id=BN00021776" ascii //weight: 1
        $x_1_2 = "http://banner.auction.co.kr/bn_redirect.asp?ID=BN00040301" ascii //weight: 1
        $x_1_3 = "http://banner.auction.co.kr/bn_redirect.asp?ID=BN00040309" ascii //weight: 1
        $x_1_4 = "http://banner.auction.co.kr/bn_redirect.asp?id=BN00017632" ascii //weight: 1
        $x_1_5 = "http://banner.auction.co.kr/bn_redirect.asp?id=BN00017628" ascii //weight: 1
        $x_1_6 = "http://click.linkprice.com/click.php?m=interpark&a=A100205584&l=0" ascii //weight: 1
        $x_1_7 = "zeroauction.co.kr/promotion_new/intro.asp?me_code=M226001" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Adclicker_BB_2147638308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adclicker.BB"
        threat_id = "2147638308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adclicker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "115"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ObtainUserAgentString" ascii //weight: 3
        $x_5_2 = "final.dll" ascii //weight: 5
        $x_2_3 = "WSPStartup" ascii //weight: 2
        $x_5_4 = "http://xml.fiestappc.com/feed.php?aid=" ascii //weight: 5
        $x_10_5 = "Layered WS2 Provider" wide //weight: 10
        $x_10_6 = "Layered Hidden Window" wide //weight: 10
        $x_10_7 = "Proxy-Connection" wide //weight: 10
        $x_10_8 = "Connection" wide //weight: 10
        $x_10_9 = "User-Agent" wide //weight: 10
        $x_10_10 = "Accept-Language" wide //weight: 10
        $x_10_11 = "Proxy-Authorization" wide //weight: 10
        $x_10_12 = " (KHTML, like Gecko)" wide //weight: 10
        $x_10_13 = "SearchString=" wide //weight: 10
        $x_10_14 = "search_keyword=+" wide //weight: 10
        $x_10_15 = "rds.yahoo.*/_ylt=*;_ylu=*/SIG=*/EXP=***http*" wide //weight: 10
        $x_10_16 = "http://playboy.com/search?SearchString=*" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((11 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((11 of ($x_10_*) and 1 of ($x_5_*))) or
            ((12 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Adclicker_11044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adclicker"
        threat_id = "11044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adclicker"
        severity = "14"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "google.cn/search?" ascii //weight: 1
        $x_1_3 = "gameyes.com" ascii //weight: 1
        $x_1_4 = "IEHelper.dll" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\Browser Helper Objects" ascii //weight: 1
        $x_1_6 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_7 = "GetClipboardData" ascii //weight: 1
        $x_1_8 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adclicker_11044_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adclicker"
        threat_id = "11044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adclicker"
        severity = "14"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "google.com" ascii //weight: 1
        $x_1_2 = "repl.dll" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\{FFFFFFFF-BBBB-4146-86FD-A722E8AB3489}" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_6 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adclicker_11044_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adclicker"
        threat_id = "11044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adclicker"
        severity = "14"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "baiduba.DLL" ascii //weight: 4
        $x_4_2 = "C:\\WINDOWS\\system32\\ieset.ini" ascii //weight: 4
        $x_2_3 = "refurl=" ascii //weight: 2
        $x_2_4 = "exid=" ascii //weight: 2
        $x_2_5 = "regURL=" ascii //weight: 2
        $x_2_6 = "seo=" ascii //weight: 2
        $x_2_7 = "smsid=" ascii //weight: 2
        $x_4_8 = "=aiyu" ascii //weight: 4
        $x_2_9 = "www.131377.com?accect" ascii //weight: 2
        $x_2_10 = "asiafind.com/go/g" ascii //weight: 2
        $x_2_11 = "shop.7cv.com/index.php?asstfrom=" ascii //weight: 2
        $x_2_12 = "cnt.zhaopin.com/Market/whole_counter.jsp?sid=" ascii //weight: 2
        $x_2_13 = "f=http://www.netxboy.com/" ascii //weight: 2
        $x_2_14 = "http://go.58.com/?f=" ascii //weight: 2
        $x_2_15 = "http://www.now.cn/?SCPMCID=" ascii //weight: 2
        $x_2_16 = "www.joyo.com/default.asp?source=ad4all" ascii //weight: 2
        $x_2_17 = "union.99jk.com/xf200/click.asp?u=1&uname=" ascii //weight: 2
        $x_2_18 = "www.131377.com?accect=" ascii //weight: 2
        $x_2_19 = "www.cncard.com/cnlink.asp?" ascii //weight: 2
        $x_5_20 = "Referer: http://www.haosoft.net/" ascii //weight: 5
        $x_5_21 = "Referer: http://www.netxboy.com/" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_2_*))) or
            ((1 of ($x_4_*) and 9 of ($x_2_*))) or
            ((2 of ($x_4_*) and 7 of ($x_2_*))) or
            ((3 of ($x_4_*) and 5 of ($x_2_*))) or
            ((1 of ($x_5_*) and 9 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 7 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 5 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_5_*) and 6 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Adclicker_11044_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adclicker"
        threat_id = "11044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adclicker"
        severity = "14"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/update/qq.dll" ascii //weight: 2
        $x_2_2 = "C:\\windows\\system32\\1028\\qqdlls.dll" ascii //weight: 2
        $x_2_3 = "C:\\WINDOWS\\system32\\ieset.ini" ascii //weight: 2
        $x_2_4 = "C:\\WINDOWS\\system32\\iebhoset.ini" ascii //weight: 2
        $x_2_5 = "C:\\WINDOWS\\baiduba\\baiduba.dll" ascii //weight: 2
        $x_2_6 = "/update/newclickupdate.exe" ascii //weight: 2
        $x_2_7 = "C:\\WINDOWS\\system32\\applog\\netuser32.ls" ascii //weight: 2
        $x_2_8 = "/update/netuser32.dll" ascii //weight: 2
        $x_2_9 = "var ad_url =" ascii //weight: 2
        $x_2_10 = "User-Agent: www.51626.net" ascii //weight: 2
        $x_2_11 = "chk_id='" ascii //weight: 2
        $x_2_12 = "/downmm/" ascii //weight: 2
        $x_2_13 = "/ad_bcast/html_show.js?a=" ascii //weight: 2
        $x_2_14 = "installhook" ascii //weight: 2
        $x_2_15 = "C:\\WINDOWS\\system32\\RgSectBk.001" ascii //weight: 2
        $x_2_16 = "C:\\WINDOWS\\system32\\shadow" ascii //weight: 2
        $x_2_17 = "C:\\WINDOWS\\system32\\drivers\\NT.SYS" ascii //weight: 2
        $x_2_18 = "C:\\WINDOWS\\system32\\drivers\\ntdisk.sys" ascii //weight: 2
        $x_2_19 = "C:\\WINDOWS\\system32\\drivers\\LSRCSYS.SYS" ascii //weight: 2
        $x_2_20 = "C:\\WINDOWS\\system32\\drivers\\xsbide.sys" ascii //weight: 2
        $x_2_21 = "_advid=" ascii //weight: 2
        $x_2_22 = "&_unionid=" ascii //weight: 2
        $x_2_23 = "&_siteid=" ascii //weight: 2
        $x_2_24 = "baibu_pg" ascii //weight: 2
        $x_2_25 = "/bdun.bsc?tn=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

