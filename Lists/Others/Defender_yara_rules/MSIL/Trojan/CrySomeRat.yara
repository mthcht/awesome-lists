rule Trojan_MSIL_CrySomeRat_AKTB_2147966952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CrySomeRat.AKTB!MTB"
        threat_id = "2147966952"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrySomeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CrySome RAT" ascii //weight: 2
        $x_2_2 = "Capturing keystrokes..." ascii //weight: 2
        $x_1_3 = "Recording on remote machine..." ascii //weight: 1
        $x_1_4 = "Listening live..." ascii //weight: 1
        $x_1_5 = "Works with process hollowing" ascii //weight: 1
        $x_1_6 = "TakeScreenshot" ascii //weight: 1
        $x_1_7 = "Keylogger" ascii //weight: 1
        $x_1_8 = "Credentials (Passwords/Cookies)" ascii //weight: 1
        $x_2_9 = "://api.telegram.org/bot" ascii //weight: 2
        $x_1_10 = "activation.php?code=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

