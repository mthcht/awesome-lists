rule Backdoor_MacOS_Mstegar_A_2147793256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Mstegar.A!xp"
        threat_id = "2147793256"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Mstegar"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UploadToRemote" ascii //weight: 1
        $x_1_2 = "MonitorThread" ascii //weight: 1
        $x_1_3 = "/Applications/Update.app" ascii //weight: 1
        $x_1_4 = "/StartupParameters.plist" ascii //weight: 1
        $x_1_5 = "AutoLaunchedApplicationDictionary" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

