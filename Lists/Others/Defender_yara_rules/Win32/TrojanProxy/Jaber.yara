rule TrojanProxy_Win32_Jaber_A_2147583848_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Jaber.A"
        threat_id = "2147583848"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "LAYERED " wide //weight: 10
        $x_10_2 = "MzName" wide //weight: 10
        $x_10_3 = "SOFTWARE\\WinSock2\\" ascii //weight: 10
        $x_1_4 = "living ever since on the " ascii //weight: 1
        $x_1_5 = "won from that history-changing " ascii //weight: 1
        $x_1_6 = "the explosion of the first atomic " ascii //weight: 1
        $x_1_7 = "But smugness can breed " ascii //weight: 1
        $x_1_8 = "carelessness. In recent years " ascii //weight: 1
        $x_1_9 = "for its successes but its failures. " ascii //weight: 1
        $x_1_10 = "secret data going missing (only " ascii //weight: 1
        $x_1_11 = "$60 million to $70 million " ascii //weight: 1
        $x_1_12 = "sell pits for $1 billion each, we " ascii //weight: 1
        $x_1_13 = "never make a profit nor should " ascii //weight: 1
        $x_1_14 = "More importantly, the 20 some " ascii //weight: 1
        $x_1_15 = "the end of the empire" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Jaber_B_2147583855_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Jaber.B"
        threat_id = "2147583855"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "LAYERED " wide //weight: 10
        $x_10_2 = "WSCWriteProviderOrder" ascii //weight: 10
        $x_10_3 = "SOFTWARE\\WinSock2\\" ascii //weight: 10
        $x_10_4 = "zupacha" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

