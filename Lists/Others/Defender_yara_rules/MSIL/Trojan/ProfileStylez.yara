rule Trojan_MSIL_ProfileStylez_A_2147647892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ProfileStylez.A"
        threat_id = "2147647892"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ProfileStylez"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TO USE THEprofile" ascii //weight: 1
        $x_1_2 = "extension_2_5_1.crx" ascii //weight: 1
        $x_1_3 = "allow us to display pop-up, pop-under and other types of advertisements" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ProfileStylez_A_2147647892_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ProfileStylez.A"
        threat_id = "2147647892"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ProfileStylez"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 20 af 00 0a 00 6f ?? 00 00 0a 13 (04|05) (08|09) 72}  //weight: 1, accuracy: Low
        $x_1_2 = "BHO_HelloWorld.IObjectWithSite.GetSite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

