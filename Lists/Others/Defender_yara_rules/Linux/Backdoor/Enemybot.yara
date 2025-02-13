rule Backdoor_Linux_Enemybot_A_2147818701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Enemybot.A"
        threat_id = "2147818701"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Enemybot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ENEMEYBOT" ascii //weight: 1
        $x_1_2 = "enemy" ascii //weight: 1
        $x_1_3 = "Data Payload" ascii //weight: 1
        $x_1_4 = "KEKSEC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

