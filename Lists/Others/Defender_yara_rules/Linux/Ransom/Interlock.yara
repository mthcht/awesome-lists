rule Ransom_Linux_Interlock_A_2147923935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Interlock.A!MTB"
        threat_id = "2147923935"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Interlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".interlock" ascii //weight: 1
        $x_1_2 = "/!__README__!.txt" ascii //weight: 1
        $x_1_3 = "_ftrylockfile" ascii //weight: 1
        $x_1_4 = "CRITICAL SECURITY ALERT" ascii //weight: 1
        $x_1_5 = {74 74 70 3a 2f 2f [0-88] 2e 6f 6e 69 6f 6e 2f 73 75 70 70 6f 72 74 2f 73 74 65 70 2e 70 68 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

