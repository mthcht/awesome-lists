rule Trojan_MSIL_Captavot_A_2147685539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Captavot.A"
        threat_id = "2147685539"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Captavot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "63"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ghost Client" ascii //weight: 1
        $x_1_2 = "Windows Library" wide //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_10_4 = "DeathByCaptcha" ascii //weight: 10
        $x_10_5 = "PollPayload" ascii //weight: 10
        $x_10_6 = "DbcPassword" ascii //weight: 10
        $x_10_7 = ":NOTIFY_OWNER:Could not download or create the new executable" wide //weight: 10
        $x_10_8 = ":NOTIFY_OWNER:Vote completed on" wide //weight: 10
        $x_10_9 = "CAPTCHA was rejected due to service overload" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

