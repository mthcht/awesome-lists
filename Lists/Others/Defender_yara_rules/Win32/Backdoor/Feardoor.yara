rule Backdoor_Win32_Feardoor_2147573281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Feardoor"
        threat_id = "2147573281"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Feardoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\FearRAT\\Server\\" ascii //weight: 1
        $x_1_2 = "\\fear\\Server\\" ascii //weight: 1
        $x_1_3 = ":gochat?roomname=" ascii //weight: 1
        $x_1_4 = "Chat Room:" ascii //weight: 1
        $x_1_5 = "Set CDAudio Door" ascii //weight: 1
        $x_1_6 = "_Oscar_IconBtn" ascii //weight: 1
        $x_1_7 = "AIM_IMessage" ascii //weight: 1
        $x_1_8 = "Olivetti 102" ascii //weight: 1
        $x_1_9 = "sendtxtfile" ascii //weight: 1
        $x_1_10 = "9ad6-0080c7e7b78d" ascii //weight: 1
        $x_1_11 = "FEAR - SERVER" ascii //weight: 1
        $x_1_12 = "_Oscar_PersistantCombo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

