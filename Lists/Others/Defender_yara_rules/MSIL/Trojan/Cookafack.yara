rule Trojan_MSIL_Cookafack_A_2147650166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cookafack.A"
        threat_id = "2147650166"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cookafack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Please Enter A your email and Password" wide //weight: 1
        $x_1_2 = "facebook_hacker_v" wide //weight: 1
        $x_1_3 = "facebook hacker v" ascii //weight: 1
        $x_1_4 = "password will be hacked by you" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

