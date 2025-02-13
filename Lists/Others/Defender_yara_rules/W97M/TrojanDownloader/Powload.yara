rule TrojanDownloader_W97M_Powload_A_2147708616_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Powload.A"
        threat_id = "2147708616"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Powload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"cmd /K \" + \"P\" & \"oWeR\" & \"s\" + \"H\" + \"elL.e\" + \"x\" + \"E" ascii //weight: 1
        $x_1_2 = "-WindowStyle hidden -ExecutionPolicy Bypass -noprofile (New-Object System.Net.WebClient).DownloadFile('http:/" ascii //weight: 1
        $x_1_3 = {27 2c 27 25 54 45 4d 50 25 5c [0-16] 2e 70 73 31 27 29 3b 20 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 6e 6f 70 72 6f 66 69 6c 65 20 2d 66 69 6c 65 20 25 54 45 4d 50 25 5c [0-16] 2e 70 73 31}  //weight: 1, accuracy: Low
        $x_1_5 = {22 63 6d 64 20 2f 4b 20 22 20 2b 20 22 70 [0-1] 22 20 26 20 22 [0-1] 57 65 52 22 20 26 20 22 53 68 22 20 2b 20 22 65 6c 6c 2e 65 22 20 2b 20 22 78 22 20 2b 20 22 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_W97M_Powload_HAZ_2147751261_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Powload.HAZ!MTB"
        threat_id = "2147751261"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Powload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Public Sub Document_Open()" ascii //weight: 1
        $x_1_2 = "= \"M\" + \"S\" + \"XM\" + \"L2\" + \".DO\" + \"M\" + \"Do\" + \"cu\" + \"m\" + \"ent\"" ascii //weight: 1
        $x_1_3 = {53 65 74 20 [0-16] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-16] 29 2e 43 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 62 36 22 20 2b 20 22 34 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 65 74 20 [0-16] 20 3d 20 [0-16] 2e 43 6f 6e 6e 65 63 74 53 65 72 76 65 72 28 29}  //weight: 1, accuracy: Low
        $x_1_5 = ".Security_.ImpersonationLevel = 874724 - 874721" ascii //weight: 1
        $x_1_6 = "= \"W\" + \"i\" + \"n\" + \"3\" + \"2_\" + \"Pr\" + \"o\" + \"c\" + \"e\" + \"s\" + \"s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Powload_HZA_2147751401_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Powload.HZA!MTB"
        threat_id = "2147751401"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Powload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_2 = "= shellobj.specialfolders(\"startup\") & \"\\\"" ascii //weight: 1
        $x_1_3 = "= \"https://immortalshield.com/read.php\"" ascii //weight: 1
        $x_1_4 = " & \"c2b72f86b8ca51642c4a902887830d3e.js\"" ascii //weight: 1
        $x_1_5 = "= CreateObject(\"msxml2.xmlhttp\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Powload_HZB_2147751874_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Powload.HZB!MTB"
        threat_id = "2147751874"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Powload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 6f 66 66 69 63 65 2d 63 6c 65 61 6e 65 72 2d 69 6e 64 65 78 2e 63 6f 6d 2f [0-32] 7c 7c 7c 6d 73 78 6d 6c 32 2e 78 6d 6c 68 74 74 70}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 4f 70 65 6e 20 22 67 65 74 22 2c 20 [0-16] 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = {53 65 74 20 [0-16] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Powload_HZC_2147753817_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Powload.HZC!MTB"
        threat_id = "2147753817"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Powload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 52 75 6e 28 22 50 6f 77 65 72 [0-8] 73 68 65 6c 6c 20 2d 65 78 [0-8] 65 63 20 42 79 70 [0-8] 61 73 73 20 2d}  //weight: 1, accuracy: Low
        $x_1_2 = "[Byte[]]$sha= iex(iex('(&(GCM *W-O*)'+ 'Net.'+'WebC'+'lient)'+'.Dow'+'nload'+'Str'+'ing" ascii //weight: 1
        $x_1_3 = "('''+'h'+'t'+'t'+'p'+':'+'/'+'/'+'w'+'w'+'w'+'.'+'m'+'9'+'c'+'.'+'n'+'e'+'t'+'/'+'u'+'p'+'l'+'o'+'a'+'d'+'s'+'/'+'1'+'5'+'8'+'7'+'2'+'5'+'6'+'0'+'9'+'7'+'2'+'.'+'j'+'p'+'g'+''')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Powload_HZD_2147754469_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Powload.HZD!MTB"
        threat_id = "2147754469"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Powload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 74 20 [0-32] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_2 = "(\"67 97 109 107 113 110 99 97 67 62 77 97 62 139 145 124 135 99 124 150 124 131 129\")" ascii //weight: 1
        $x_1_3 = "(\"62 77 135 62 134 146 146 142 88 77 77 84 81 76 80 83 78 76 82 80 76 81 82 77 156 128 147 138 133 134 146 77 " ascii //weight: 1
        $x_1_4 = "(\"62 77 135 62 134 146 146 142 145 88 77 77 84 81 76 80 83 78 76 82 80 76 81 82 77 156 128 147 138 133 134 146 77 " ascii //weight: 1
        $x_1_5 = "76 139 145 135 62 77 143 140 62\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

