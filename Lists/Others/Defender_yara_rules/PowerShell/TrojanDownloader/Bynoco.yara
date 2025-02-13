rule TrojanDownloader_PowerShell_Bynoco_2147751866_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/Bynoco!MTB"
        threat_id = "2147751866"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "Bynoco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wershell \" & \"(NEw-objE\" & lll & \"t \" & \"system.net.wEBclIenT).DownLoAdfIlE" ascii //weight: 1
        $x_1_2 = "https://c.top4top.io/p_1752i2rzz1.jpg" ascii //weight: 1
        $x_1_3 = "ENv:TEMP\\vhf.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_PowerShell_Bynoco_2147751866_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/Bynoco!MTB"
        threat_id = "2147751866"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "Bynoco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set xHttp = CreateObject(\"Microsoft.XMLHTTP\")" ascii //weight: 1
        $x_1_2 = "xHttp.Open \"GET\", \"http://172.16.70.10/ps1_b64.crt\", False" ascii //weight: 1
        $x_1_3 = ".savetofile \"encoded_ps1.crt\"" ascii //weight: 1
        $x_1_4 = "Shell (" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_PowerShell_Bynoco_2147751866_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/Bynoco!MTB"
        threat_id = "2147751866"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "Bynoco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"PowerShell -nologo -noninteractive -windowStyle hidden -Command" ascii //weight: 1
        $x_1_2 = "(New-Object System.Net.WebClient).Downloadstring" ascii //weight: 1
        $x_1_3 = "https://iplogg','er.org/2ovA93" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_PowerShell_Bynoco_2147751866_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/Bynoco!MTB"
        threat_id = "2147751866"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "Bynoco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Net.WebcL`IENt).('Down'+'loadFile').\"Invoke" ascii //weight: 1
        $x_1_2 = "ttps://tinyurl.com/y3pwsy3s','an.exe" ascii //weight: 1
        $x_1_3 = "stARt`-slE`Ep 20; Move-Item \"an.exe\" -Destination \"${enV`:appdata}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_PowerShell_Bynoco_2147751866_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/Bynoco!MTB"
        threat_id = "2147751866"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "Bynoco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell.exe -WindowStyle Hidden -ExecutionPolicy" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f 77 65 65 73 68 6f 70 70 69 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 49 44 33 2f [0-4] 2f [0-8] 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_3_3 = "Start-Process -FilePath \"C:\\Users\\Public\\adlhvmc.exe" ascii //weight: 3
        $x_3_4 = "Start-Process -FilePath \"C:\\Users\\Public\\Documents\\jaecyyv.exe" ascii //weight: 3
        $x_3_5 = "Start-Process -FilePath \"C:\\Users\\Public\\Documents\\lvmisap.exe" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_PowerShell_Bynoco_2147751866_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/Bynoco!MTB"
        threat_id = "2147751866"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "Bynoco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Chr(80) + Chr(79) + \"W\" + \"E\" + \"r\" + \"shell\"" ascii //weight: 1
        $x_1_2 = "-ep bypass -Command \"\"\" + Cmd + \" '\" + uri + \"' -OutFile '\" + file_bat_complete_path + \"'\"\"; .\\\" + pay" ascii //weight: 1
        $x_1_3 = "= first_oct + \".\" + second_oct + \".\" + third_oct + \".\" + fourth_oct" ascii //weight: 1
        $x_1_4 = "= Shell(\"c\" + \"m\" + \"d\" + \" /K \" + file_bat_complete_path, vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_PowerShell_Bynoco_2147751866_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/Bynoco!MTB"
        threat_id = "2147751866"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "Bynoco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "strFileExists = Dir(\"C:\\\" + \"\\aa\" + \"a_T\" + \"ouch\" + \"Me\" + \"N\" + \"ot.txt\")" ascii //weight: 1
        $x_1_2 = "Call GetObject(StrReverse(\"ss\" + \"ec\" + \"orP_\" + \"23niW\" + \":2\" + \"vmi\" + \"c\\t\" + \"oor:\" + \"stm\" + \"gm\" + \"n\" + \"iw\")). _" ascii //weight: 1
        $x_1_3 = "Create(StrReverse(\"=" ascii //weight: 1
        $x_1_4 = "e- ne\" + \"ddi\" + \"h ely\" + \"tswodn\" + \"iw- l\" + StrReverse(\"hel\") + \"sr\" + \"e\" + \"w\" + \"op\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_PowerShell_Bynoco_2147751866_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/Bynoco!MTB"
        threat_id = "2147751866"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "Bynoco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dir(\"C:\\Users\\\" & Environ(\"username\") & \"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\windows_defender.hta\")" ascii //weight: 1
        $x_1_2 = "= \"PowerShell -windowstyle hidden wget http://sv2.s2u.es/exploit/adjunto.hta" ascii //weight: 1
        $x_1_3 = "-OutFile \"\"\"\"\"\"C:\\Users\\enacher\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\windows_defender.hta\"\"\"\"\"\"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_PowerShell_Bynoco_2147751866_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/Bynoco!MTB"
        threat_id = "2147751866"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "Bynoco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "strFileExists = Dir(\"C:\\\" + \"\\aa\" + \"a_T\" + \"ouch\" + \"Me\" + \"N\" + \"ot_.txt\")" ascii //weight: 1
        $x_1_2 = "Call GetObject(StrReverse(\"ss\" + \"ec\" + \"o\" + StrReverse(\"_Pr\") + \"23niW\" + \":2\" + \"vmi\" + \"c\\t\" + \"oor:\" + \"stm\" + \"gm\" + \"n\" + \"iw\")). _" ascii //weight: 1
        $x_1_3 = "Create(StrReverse(\"=" ascii //weight: 1
        $x_1_4 = "e- ne\" + \"ddi\" + \"h ely\" + \"tswodn\" + \"iw- l\" + StrReverse(\"hel\") + StrReverse(\"rs\") + \"e\" + \"w\" + \"op\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

