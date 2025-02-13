rule TrojanDownloader_O97M_Netwire_YA_2147758606_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Netwire.YA!MTB"
        threat_id = "2147758606"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "officeservicecorp.biz/" ascii //weight: 1
        $x_1_2 = "powershell.exe -Command IEX (New-Object('Net.WebClient'))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Netwire_YB_2147762914_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Netwire.YB!MTB"
        threat_id = "2147762914"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OutFile ('test5'+'.exe'); &('./test5'+'.e'+'x'+'e')B" ascii //weight: 1
        $x_1_2 = "powershell.exe -w h I`wR" ascii //weight: 1
        $x_1_3 = "('ht'+'tps://tinyurl.com/yyclvuju')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Netwire_YG_2147763543_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Netwire.YG!MTB"
        threat_id = "2147763543"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ht'+'tps://cutt.ly/dfQBUYc" ascii //weight: 1
        $x_1_2 = "powershell.exe -w h I`wR" ascii //weight: 1
        $x_1_3 = "-OutFile ('test5'+'.exe')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Netwire_YAJ_2147765317_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Netwire.YAJ!MTB"
        threat_id = "2147765317"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DownloadFile').Invoke(('ht'+'tps://cutt.ly/DgwXCmM" ascii //weight: 1
        $x_1_2 = "po^wer^shell -w 1 Start-Sleep 16; sTArt-`P`R`ocess $env:appdata\\kc.exe" ascii //weight: 1
        $x_1_3 = "p^ower^shell -w 1 Start-Sleep 10; Move-Item \"kc.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Netwire_CT_2147769935_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Netwire.CT!MTB"
        threat_id = "2147769935"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(nEw-oB`jecT Net.WebcL`IENt)" ascii //weight: 1
        $x_1_2 = "('Down'+'loadFile')" ascii //weight: 1
        $x_1_3 = "Invoke\"('https://cutt.ly/vhcyHuc','pd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Netwire_SS_2147776915_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Netwire.SS!MTB"
        threat_id = "2147776915"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {78 20 3d 20 73 73 73 73 73 73 73 28 22 61 22 2c 20 [0-15] 29}  //weight: 1, accuracy: Low
        $x_1_2 = "For lonDataPtr = 1 To (Len(DataIn) / 2)" ascii //weight: 1
        $x_1_3 = "intXOrValue1 = Val(\"&H\" & (Mid$(DataIn, (2 * lonDataPtr) - 1, 2)))" ascii //weight: 1
        $x_1_4 = "intXOrValue2 = Asc(Mid$(CodeKey, ((lonDataPtr Mod Len(CodeKey)) + 1), 1))" ascii //weight: 1
        $x_1_5 = "retval = Shell(sssssss)" ascii //weight: 1
        $x_1_6 = "strDataOut = strDataOut + Chr(intXOrValue1 Xor intXOrValue2)" ascii //weight: 1
        $x_1_7 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 [0-3] 44 69 6d 20 [0-15] 20 41 73 20 53 74 72 69 6e 67 [0-3] 01 20 3d 20 01 20 2b 20 22 30 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Netwire_PDB_2147833172_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Netwire.PDB!MTB"
        threat_id = "2147833172"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd1(XxX, aAa) + URL(XxX, aAa) + cmd2(XxX, aAa)" ascii //weight: 1
        $x_1_2 = {53 68 65 6c 6c 20 [0-10] 2c 20 76 62 48 69 64 65}  //weight: 1, accuracy: Low
        $x_1_3 = "URL = \"\"\"exe.lld/lmth/moc.mixeplut//:ptth\"" ascii //weight: 1
        $x_1_4 = "URL = \"\"\"exe.derraj/mtyap/moc.enydlelet//:sptth\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

