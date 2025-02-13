rule TrojanClicker_MSIL_Doviali_A_2147641137_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Doviali.A"
        threat_id = "2147641137"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Doviali"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\VoiD\\" ascii //weight: 1
        $x_1_2 = "\\obj\\Release\\AffiliateDLer.pdb" ascii //weight: 1
        $x_1_3 = "www.zwinky.com" wide //weight: 1
        $x_1_4 = "AffiliateDLer.Properties.Resources" wide //weight: 1
        $x_1_5 = "/clicks/settings/active_x/" wide //weight: 1
        $x_1_6 = "/clicks/splash/cookie_enabled" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

