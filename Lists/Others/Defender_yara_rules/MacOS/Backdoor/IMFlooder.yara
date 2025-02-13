rule Backdoor_MacOS_IMFlooder_A_2147814535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/IMFlooder.A!xp"
        threat_id = "2147814535"
        type = "Backdoor"
        platform = "MacOS: "
        family = "IMFlooder"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Messenger ID of the victim" ascii //weight: 1
        $x_1_2 = "IM FloodVisible" ascii //weight: 1
        $x_1_3 = "mark.macintosh@gmail.com" ascii //weight: 1
        $x_1_4 = "YahooMessengerChatFlooder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

