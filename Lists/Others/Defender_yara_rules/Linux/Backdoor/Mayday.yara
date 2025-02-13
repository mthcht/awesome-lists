rule Backdoor_Linux_Mayday_A_2147824657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mayday.A!xp"
        threat_id = "2147824657"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mayday"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 ec 0c 68 60 9a 0c 08 e8 b9 15 00 00 83 c4 10 83 ec 0c 8d 45 90 50 e8 7d 00 00 00 83 c4 10 83 ec 0c 8d 45 90 50}  //weight: 1, accuracy: High
        $x_1_2 = {83 ec 04 68 00 04 00 00 8d 85 f0 fb ff ff 50 ff 75 f4 e8 a7 1b 00 00 83 c4 10 89 45 f8 83 7d f8 00 7e 2c 8b 55 f8 8d 45 fc 01 10 8b 45 f8 83 ec 04 50 8d 85 f0 fb ff ff 50 ff 75 f0 e8 9a 51 00 00 83 c4 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

