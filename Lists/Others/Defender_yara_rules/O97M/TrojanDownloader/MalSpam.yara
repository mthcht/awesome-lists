rule TrojanDownloader_O97M_MalSpam_B_2147744527_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/MalSpam.B!MTB"
        threat_id = "2147744527"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "MalSpam"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+ Foglio1.ff(Cells(u, yz)):" ascii //weight: 1
        $x_1_2 = "= Asc(Left(Trim(Application.Caption), 1))" ascii //weight: 1
        $x_1_3 = "= \"\": Shell zu & fra & Cells(yz * 2, yz / 5) & fraa, msoDocInspectorStatusDocOk" ascii //weight: 1
        $x_1_4 = "(Right(fff, 1) Mod 2 = 0," ascii //weight: 1
        $x_1_5 = "If CInt(Mid(fff, ffa *" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_MalSpam_C_2147744679_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/MalSpam.C!MTB"
        threat_id = "2147744679"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "MalSpam"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"exe\"" ascii //weight: 1
        $x_1_2 = "\".\" & _" ascii //weight: 1
        $x_1_3 = {24 45 4e 76 3a 74 65 4d 70 5c [0-16] 2e 22 20 26}  //weight: 1, accuracy: Low
        $x_1_4 = "\"\" & \" \" &" ascii //weight: 1
        $x_1_5 = "Call Shell$(" ascii //weight: 1
        $x_1_6 = "= \"(NEw-objE\" & \"c\"" ascii //weight: 1
        $x_1_7 = "= \"%temp%\" &" ascii //weight: 1
        $x_1_8 = "= \"\\\"" ascii //weight: 1
        $x_1_9 = "Application.Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_MalSpam_AR_2147754573_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/MalSpam.AR!MTB"
        threat_id = "2147754573"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "MalSpam"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 3a 20 57 53 63 72 69 70 74 2e 51 75 69 74 20 3d 20 28 22 22 20 26 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 29 29 2e 52 75 6e 28 28 [0-8] 29 2c 20 28 [0-1] 29 2c 20 28 30 29 29 29 3a 20 57 53 63 72 69 70 74 2e 51 75 69 74 3a 20 4d 73 67 42 6f 78 20 22 22 3a 20 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 43 6c 6f 73 65 20 46 61 6c 73 65 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 3a 20 57 53 63 72 69 70 74 2e 51 75 69 74 20 3d 20 28 22 22 20 26 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 29 29 2e 52 75 6e 28 28 [0-5] 29 2c 20 28 30 29 2c 20 28 30 29 29 29 3a 20 57 53 63 72 69 70 74 2e 51 75 69 74 3a 20 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 43 6c 6f 73 65 20 46 61 6c 73 65 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 61 6e 67 65 28 22 [0-18] 22 29 2e 53 70 65 63 69 61 6c 43 65 6c 6c 73 28 78 6c 43 6f 6e 73 74 61 6e 74 73 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_MalSpam_RDU_2147754994_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/MalSpam.RDU!MTB"
        threat_id = "2147754994"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "MalSpam"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "owershell.exe -Command IEX" ascii //weight: 1
        $x_1_2 = "New-Object('Net.WebClient')" ascii //weight: 1
        $x_1_3 = "DoWnloAdsTrInG'('" ascii //weight: 1
        $x_1_4 = "ht'+'tps://pastebin.com/raw/fASw9wCZ')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

