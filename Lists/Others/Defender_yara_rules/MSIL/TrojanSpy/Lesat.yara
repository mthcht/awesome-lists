rule TrojanSpy_MSIL_Lesat_A_2147696050_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Lesat.A"
        threat_id = "2147696050"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lesat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%screen%" ascii //weight: 1
        $x_1_2 = "%webcam%" ascii //weight: 1
        $x_1_3 = "%antis%" ascii //weight: 1
        $x_1_4 = "%persistance%" ascii //weight: 1
        $x_1_5 = "%Killer%" ascii //weight: 1
        $x_1_6 = "%disablefolder%" ascii //weight: 1
        $x_1_7 = "%disablemscon%" ascii //weight: 1
        $x_1_8 = "%disableCP%" ascii //weight: 1
        $x_1_9 = "%disableSR%" ascii //weight: 1
        $x_1_10 = "%disablereg%" ascii //weight: 1
        $x_1_11 = "%disablerun%" ascii //weight: 1
        $x_1_12 = "%disablecmd%" ascii //weight: 1
        $x_1_13 = "%disabletask%" ascii //weight: 1
        $x_1_14 = "%disableuac%" ascii //weight: 1
        $x_1_15 = "%downloader%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule TrojanSpy_MSIL_Lesat_A_2147696050_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Lesat.A"
        threat_id = "2147696050"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lesat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Steal_Chrome" wide //weight: 1
        $x_1_2 = "Steal_CoreFTP" wide //weight: 1
        $x_1_3 = "Steal_DynDNS" wide //weight: 1
        $x_1_4 = "Steal_FTPCommande" wide //weight: 1
        $x_1_5 = "Steal_FileZilla" wide //weight: 1
        $x_1_6 = "Steal_Firefox" wide //weight: 1
        $x_1_7 = "Steal_FlashFXP" wide //weight: 1
        $x_1_8 = "Steal_IDM" wide //weight: 1
        $x_1_9 = "Steal_IE" wide //weight: 1
        $x_1_10 = "Steal_IMVU" wide //weight: 1
        $x_1_11 = "Steal_JDownloader" wide //weight: 1
        $x_1_12 = "Steal_KeyRec" wide //weight: 1
        $x_1_13 = "Steal_MSN" wide //weight: 1
        $x_1_14 = "Steal_NO_IP" wide //weight: 1
        $x_1_15 = "Steal_Opera" wide //weight: 1
        $x_1_16 = "Steal_Paltalk" wide //weight: 1
        $x_1_17 = "Steal_Pidgin" wide //weight: 1
        $x_1_18 = "Steal_SmartFTP" wide //weight: 1
        $x_1_19 = "Steal_Steam" wide //weight: 1
        $x_1_20 = "Steal_Yahoo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

