rule Backdoor_MSIL_Kuribot_A_2147726530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Kuribot.A!bit"
        threat_id = "2147726530"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kuribot"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://telegra.ph/Kur-" wide //weight: 10
        $x_1_2 = "Kuriyama.install" ascii //weight: 1
        $x_1_3 = "Kuriyama.control" ascii //weight: 1
        $x_1_4 = "Kuriyama.ddos" ascii //weight: 1
        $x_1_5 = "Kuriyama.vmdetect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

