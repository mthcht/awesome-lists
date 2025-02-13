rule Backdoor_MSIL_Arechbot_A_2147735459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Arechbot.A!bit"
        threat_id = "2147735459"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Arechbot"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "real_pro_ru_new" ascii //weight: 1
        $x_1_2 = "ArechClient2.Code" ascii //weight: 1
        $x_1_3 = "ReceiveCaptureRequest" ascii //weight: 1
        $x_1_4 = "SFSAFSSASFDASF" wide //weight: 1
        $x_1_5 = "{{ Type = {0}, ConnectionType = {1}, SessionID = {2}, BotName = {3}, BotOS = {4} }}" wide //weight: 1
        $x_1_6 = "/C start chrome.exe --user-data-dir=" wide //weight: 1
        $x_1_7 = "schtasks /create /tn \\System\\SecurityService /tr %userprofile%\\AppData\\Roaming\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

