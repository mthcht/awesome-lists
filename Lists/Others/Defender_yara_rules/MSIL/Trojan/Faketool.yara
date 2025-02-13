rule Trojan_MSIL_Faketool_2147706008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Faketool"
        threat_id = "2147706008"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Faketool"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKEY_CURRENT_USER\\Software\\HackFacebookProfiles" wide //weight: 1
        $x_1_2 = "webbrowserpassview.zip" wide //weight: 1
        $x_1_3 = "webropv.zip" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

