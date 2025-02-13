rule Trojan_MSIL_VayneRat_CXJP_2147888469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VayneRat.CXJP!MTB"
        threat_id = "2147888469"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VayneRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Vayne Rat - Client" ascii //weight: 1
        $x_1_2 = "SELECT * FROM AntivirusProduct" wide //weight: 1
        $x_1_3 = "Windows Defender" wide //weight: 1
        $x_1_4 = "logins" wide //weight: 1
        $x_1_5 = "username_value" wide //weight: 1
        $x_1_6 = "password_value" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

