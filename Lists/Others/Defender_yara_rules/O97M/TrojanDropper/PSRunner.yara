rule TrojanDropper_O97M_PSRunner_G_2147757690_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/PSRunner.G!MSR"
        threat_id = "2147757690"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "PSRunner"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "706f7765727368656c6c2049455820284e65772d4f626a656374204e65742e576562436c69656e74292e446f776e6c" ascii //weight: 2
        $x_2_2 = "(\"6f6164537472696e67282768747470" ascii //weight: 2
        $x_3_3 = "powershell.exe -W Hidden -Exec Bypass -Command cd /;" ascii //weight: 3
        $x_1_4 = "+ 'TVq';\" & _" ascii //weight: 1
        $n_10_5 = "You are about to run a demo attack scenario provided as part of the Microsoft WDATP Preview/Trial program" ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

