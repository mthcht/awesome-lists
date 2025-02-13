rule Backdoor_Linux_PingBack_A_2147813237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/PingBack.A!dha"
        threat_id = "2147813237"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "PingBack"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ba 01 00 00 00 be 03 00 00 00 bf 02 00 00 00 e8 ?? ?? ?? ?? 89 45 d4 83 7d d4 ff}  //weight: 5, accuracy: Low
        $x_1_2 = "input proper bind ip addr" ascii //weight: 1
        $x_1_3 = "can't bind to addr" ascii //weight: 1
        $x_1_4 = "[watchdog/1]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

