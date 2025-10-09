rule TrojanDropper_W97M_Avosim_A_2147717729_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:W97M/Avosim.A"
        threat_id = "2147717729"
        type = "TrojanDropper"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Avosim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".vbs\"" ascii //weight: 1
        $x_1_2 = ".Run cmd" ascii //weight: 1
        $x_1_3 = "\"schtasks /create /F /sc minute /mo" ascii //weight: 1
        $x_1_4 = "= CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_5 = "\"powershell " ascii //weight: 1
        $n_100_6 = "http://www.nissay.co.jp/kojin/shohin" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule TrojanDropper_W97M_Avosim_A_2147717729_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:W97M/Avosim.A"
        threat_id = "2147717729"
        type = "TrojanDropper"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Avosim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "updpath = envstr & fdname & \"\\upd.vbs\"" ascii //weight: 1
        $x_1_2 = "dnpath = envstr & fdname & \"\\dn.ps1\"" ascii //weight: 1
        $x_1_3 = ".Run \"schtasks /create /F /sc minute /mo \" & tskmin & \" /tn \" & Chr(34) & tskname & Chr(34) & \" /tr \" _" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_W97M_Avosim_B_2147721932_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:W97M/Avosim.B"
        threat_id = "2147721932"
        type = "TrojanDropper"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Avosim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Run \"cmd.exe  /c echo \" & Chr(" ascii //weight: 1
        $x_1_2 = "powershell.exe [IO.File]::WriteAllBytes(" ascii //weight: 1
        $x_1_3 = "schtasks /create /F /sc minute /mo 3 /tn" ascii //weight: 1
        $x_1_4 = ".Run \"cmd.exe  /c echo \" & \"Set" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

