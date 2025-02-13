rule TrojanDownloader_O97M_Lokibot_NA_2147768122_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Lokibot.NA!MTB"
        threat_id = "2147768122"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 73 70 61 72 65 70 61 72 74 69 72 61 6e 2e 63 6f 6d 2f 6a 73 2f 64 31 2f [0-20] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 22 20 2b 22 [0-50] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {53 68 65 6c 6c 28 [0-50] 2c}  //weight: 1, accuracy: Low
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_5 = "urlmon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Lokibot_NB_2147768126_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Lokibot.NB!MTB"
        threat_id = "2147768126"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://piratesmoker.com/purchase%20order/Purchase%20Order.exe" ascii //weight: 1
        $x_1_2 = "C:\\Users\\Public\\Downloads\\\" +\"chrdtymemnnycbulxahbhhackrynkjnebttdolbifypac.exe" ascii //weight: 1
        $x_1_3 = {3d 20 53 68 65 6c 6c 28 [0-50] 2c 20 76 62 4e 6f 72 6d 61 6c 4e 6f 46 6f 63 75 73}  //weight: 1, accuracy: Low
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_5 = "urlmon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Lokibot_RV_2147769051_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Lokibot.RV!MTB"
        threat_id = "2147769051"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "https://cdn.discordapp.com/attachments/780223158832988201/780380758862069760/RJWV.exe" ascii //weight: 2
        $x_2_2 = "http://piratesmoker.com/ORDER%20FORM%20DENK/ORDER%20FORM%20DENK.exe" ascii //weight: 2
        $x_2_3 = "Environ(\"APPDATA\") +\"apghsobievlaqskkfyvavvjwebwehfvinuqadwmxvwvlw.exe\",0,0" ascii //weight: 2
        $x_2_4 = "C:\\Users\\Public\\Downloads\\\" +\"fbyrhitepgzqztnqpxvsnzqkvnggnliadocjvcenxlsfk.exe\",0,0" ascii //weight: 2
        $x_1_5 = {53 68 65 6c 6c 28 [0-50] 2c 20 76 62 4e 6f 72 6d 61 6c 4e 6f 46 6f 63 75 73 29}  //weight: 1, accuracy: Low
        $x_1_6 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_7 = "urlmon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Lokibot_RVA_2147771847_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Lokibot.RVA!MTB"
        threat_id = "2147771847"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 6f 6e 65 72 72 6f 72 67 6f 74 6f 65 72 72 6f 72 68 61 6e 64 6c 65 72 63 6f 6e 73 74 64 6f 77 6e 6c 6f 61 64 5f 75 72 6c 61 73 73 74 72 69 6e 67 3d 22 68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 31 32 36 35 35 39 32 36 38 30 37 30 30 37 31 31 30 30 36 2f 31 32 36 35 38 32 33 39 31 37 31 30 31 30 32 33 32 35 32 2f [0-15] 2e 65 78 65 3f 65 78 3d}  //weight: 1, accuracy: Low
        $x_1_2 = "=environ$(\"tmp\")&\"\\downloaded_file.exe\"" ascii //weight: 1
        $x_1_3 = "=createobject(\"msxml2.xmlhttp\")xmlhttp.open\"get\",url,falsexmlhttp.send" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Lokibot_LPK_2147816784_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Lokibot.LPK!MTB"
        threat_id = "2147816784"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 32 30 2e 34 30 2e 39 37 2e 39 34 2f 74 37 62 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f [0-31] 2e 62 61 74 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-47] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

