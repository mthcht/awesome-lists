rule Trojan_MSIL_KalkulatorRAT_AMTB_2147982533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KalkulatorRAT!AMTB"
        threat_id = "2147982533"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KalkulatorRAT"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "KalkulatorRAT" ascii //weight: 3
        $x_3_2 = "KalkulatorRAT.pdb" ascii //weight: 3
        $x_1_3 = "kalk_fsnd_" ascii //weight: 1
        $x_1_4 = "KalkulatorRAT.PasswordGrabber" ascii //weight: 1
        $x_1_5 = "Software\\KalkulatorRAT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

