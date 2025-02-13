rule Backdoor_MSIL_Minerbot_A_2147725067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Minerbot.A"
        threat_id = "2147725067"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Minerbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "downloadAndExcecute" ascii //weight: 1
        $x_1_2 = "tmgrCheck" ascii //weight: 1
        $x_1_3 = "appShortcutToStartup" ascii //weight: 1
        $x_1_4 = "/cmd.php" wide //weight: 1
        $x_1_5 = "/C schtasks /create /tn \\System\\SecurityServiceUpdate /tr %userprofile%\\AppData\\Roaming\\Windows\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

