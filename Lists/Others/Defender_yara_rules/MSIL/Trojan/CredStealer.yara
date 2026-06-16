rule Trojan_MSIL_CredStealer_AMTB_2147971672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CredStealer!AMTB"
        threat_id = "2147971672"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CredStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cred_steal" ascii //weight: 1
        $x_1_2 = "HelloPayload" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\SoftwareExpress\\SiTef" ascii //weight: 1
        $x_1_4 = "C:\\GertecTEF" ascii //weight: 1
        $x_1_5 = "credstealer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

