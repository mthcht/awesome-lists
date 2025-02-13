rule Trojan_AndroidOS_Lozfoon_A_2147661791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Lozfoon.A"
        threat_id = "2147661791"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Lozfoon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "appli/addressBookRegist" ascii //weight: 1
        $x_1_2 = "APPLI_MAIL_DIV_PARAM" ascii //weight: 1
        $x_1_3 = "##addressName##" ascii //weight: 1
        $x_1_4 = "contact_methods._id = ?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

