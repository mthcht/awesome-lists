rule Backdoor_Linux_Neko_2147765650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Neko.ab!MTB"
        threat_id = "2147765650"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Neko"
        severity = "Critical"
        info = "ab: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 75 73 79 62 6f 78 20 77 67 65 74 20 2d 67 20 [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 20 2d 6c 20 2f 74 6d 70 2f [0-16] 20 2d 72 20 2f [0-16] 2f [0-16] 2e 6d 69 70 73 3b 63 68 6d 6f 64 20 37 37 37 20 2f 74 6d 70 2f [0-16] 3b 2f 74 6d 70 2f [0-16] 20 [0-16] 2e 6d 69 70 73 3b 72 6d 20 2d 72 66 20 2f 74 6d 70 2f}  //weight: 1, accuracy: Low
        $x_1_2 = {73 68 65 6c 6c 3f 63 64 20 2f 74 6d 70 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 5c 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f [0-16] 2f [0-16] 2e 61 72 6d 3b 20 63 68 6d 6f 64 20 37 37 37 20 05 2e 61 72 6d 3b 20 2e 2f 05 2e 61 72 6d [0-21] 61 72 6d 34 3b 72 6d 20 2d 72 66 20 05 2e 61 72 6d}  //weight: 1, accuracy: Low
        $x_1_3 = "QBotBladeSPOOKY" ascii //weight: 1
        $x_1_4 = "Tsunami" ascii //weight: 1
        $x_1_5 = "Corona" ascii //weight: 1
        $x_1_6 = "trojan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

