rule Trojan_MSIL_Startpage_H_2147658544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Startpage.H"
        threat_id = "2147658544"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "6d788052/program/stats?homepage=1" wide //weight: 2
        $x_2_2 = "h+E4Y6I2s3aQnw5urjZr42" wide //weight: 2
        $x_1_3 = "poiskweb.com" wide //weight: 1
        $x_2_4 = "h+E4Y6I2s7aZMnhoYppjEX30ng==" wide //weight: 2
        $x_2_5 = "h+E4Y6I2s7V3/oFq7MD6rfzAqqPfbw==" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Startpage_XW_2147696089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Startpage.XW"
        threat_id = "2147696089"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"urls_to_restore_on_startup\": [ \"http://www.google.com.tr/\" ]" ascii //weight: 1
        $x_1_2 = "\"startup_list\": [ 1, \"https://www.google.com.tr/\", \"https://www.google.com/\" ]" ascii //weight: 1
        $x_1_3 = "\"last_prompted_google_url\": \"https://www.google.com.tr/\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

