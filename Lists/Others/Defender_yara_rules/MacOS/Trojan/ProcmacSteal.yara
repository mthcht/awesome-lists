rule Trojan_MacOS_ProcmacSteal_DB_2147976805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/ProcmacSteal.DB!MTB"
        threat_id = "2147976805"
        type = "Trojan"
        platform = "MacOS: "
        family = "ProcmacSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "i am botking" ascii //weight: 1
        $x_1_2 = "pen_v2" ascii //weight: 1
        $x_1_3 = "<key>RunAtLoad</key>" ascii //weight: 1
        $x_1_4 = "<string>/bin/zsh</string>" ascii //weight: 1
        $x_1_5 = "radr://5614542" ascii //weight: 1
        $x_1_6 = "capture(pid=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

