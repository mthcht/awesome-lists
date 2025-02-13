rule DDoS_Linux_Znaich_BD_2147809147_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Znaich.BD!MTB"
        threat_id = "2147809147"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Znaich"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 54 24 0c 89 54 24 08 c7 44 24 ?? ?? ?? ?? ?? 89 04 24 e8 ?? ?? ?? ?? 8d 95 e8 fa ff ff 89 14 24}  //weight: 1, accuracy: Low
        $x_1_2 = {89 74 24 0c 83 c6 01 89 7c 24 10 c7 44 24 ?? ?? ?? ?? ?? c7 44 24 04 00 04 00 00 89 1c 24 e8 ?? ?? ?? ?? 89 1c 24 e8 ?? ?? ?? ?? 89 1c 24 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 0c 89 74 24 18 89 74 24 14 89 74 24 10 89 44 24 0c 8d 85 e3 fe ff ff 89 44 24 08 c7 44 24 ?? ?? ?? ?? ?? 89 1c 24 e8 ?? ?? ?? ?? 89 1c 24}  //weight: 1, accuracy: Low
        $x_1_4 = {89 54 24 10 89 3c 24 89 5c 24 0c c7 44 24 ?? ?? ?? ?? ?? c7 44 24 ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 3c 24 e8 ?? ?? ?? ?? c7 04 24 02 00 00 00 e8 ?? ?? ?? ?? 8b 85 e0 ea ff ff}  //weight: 1, accuracy: Low
        $x_1_5 = "COMMAND_DDOS_STOP" ascii //weight: 1
        $x_1_6 = "sed -i '/\\/etc\\/cron.hourly\\/cron.sh/d' /etc/crontab" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

