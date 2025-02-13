rule PWS_MSIL_Silog_A_2147708475_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Silog.A"
        threat_id = "2147708475"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Silog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "---- Silent Logger - Reported Logs ----" wide //weight: 1
        $x_1_2 = "StealerRunner" ascii //weight: 1
        $x_1_3 = "KeyloggerTimer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

