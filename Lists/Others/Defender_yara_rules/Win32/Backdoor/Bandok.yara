rule Backdoor_Win32_Bandok_A_2147592515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bandok.gen!A"
        threat_id = "2147592515"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandok"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "zasucks" ascii //weight: 20
        $x_10_2 = "bndk13me" ascii //weight: 10
        $x_10_3 = "pws2.bndk" ascii //weight: 10
        $x_1_4 = "&contome&" ascii //weight: 1
        $x_1_5 = "&deldir&" ascii //weight: 1
        $x_1_6 = "&delfile&" ascii //weight: 1
        $x_1_7 = "&dirfiles&" ascii //weight: 1
        $x_1_8 = "&dorediboo&" ascii //weight: 1
        $x_1_9 = "&drvs&" ascii //weight: 1
        $x_1_10 = "&exec&" ascii //weight: 1
        $x_1_11 = "&getreg&" ascii //weight: 1
        $x_1_12 = "&gimmemirror&" ascii //weight: 1
        $x_1_13 = "&gimmewin&" ascii //weight: 1
        $x_1_14 = "&httpoff&" ascii //weight: 1
        $x_1_15 = "&httpservon&" ascii //weight: 1
        $x_1_16 = "&itsoffkey&" ascii //weight: 1
        $x_1_17 = "&mirstop&" ascii //weight: 1
        $x_1_18 = "&mkdir&" ascii //weight: 1
        $x_1_19 = "&offkey&" ascii //weight: 1
        $x_1_20 = "&onkey&" ascii //weight: 1
        $x_1_21 = "&postthem&" ascii //weight: 1
        $x_1_22 = "&redistop&" ascii //weight: 1
        $x_1_23 = "&regcon&" ascii //weight: 1
        $x_1_24 = "&rshell&" ascii //weight: 1
        $x_1_25 = "&sshell&" ascii //weight: 1
        $x_1_26 = "&visitsite&" ascii //weight: 1
        $x_1_27 = "&winaction&" ascii //weight: 1
        $x_1_28 = "ar.bndk" ascii //weight: 1
        $x_1_29 = "%s//TV.bndk" ascii //weight: 1
        $x_1_30 = "%s//ieg.bndk" ascii //weight: 1
        $x_1_31 = "RecordCam" ascii //weight: 1
        $x_1_32 = "StopCam" ascii //weight: 1
        $x_1_33 = "bitchcn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 30 of ($x_1_*))) or
            ((1 of ($x_20_*) and 30 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 20 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

