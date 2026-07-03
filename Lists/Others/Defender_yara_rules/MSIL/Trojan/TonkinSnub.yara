rule Trojan_MSIL_TonkinSnub_A_2147972813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TonkinSnub.A!dha"
        threat_id = "2147972813"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TonkinSnub"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Expected Salary:" wide //weight: 1
        $x_1_2 = "Under Technical Review" wide //weight: 1
        $x_1_3 = "Pending Final Approval" wide //weight: 1
        $x_1_4 = "Login Failed!" wide //weight: 1
        $x_1_5 = "Upload Resume" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

