rule PWS_MSIL_Inssteal_A_2147764109_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Inssteal.A!MTB"
        threat_id = "2147764109"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Inssteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "forstealany" ascii //weight: 1
        $x_1_2 = "hackerme" ascii //weight: 1
        $x_1_3 = "C:\\Users\\hacke\\source\\repos" ascii //weight: 1
        $x_1_4 = "https://www.instagram.com/" ascii //weight: 1
        $x_1_5 = "ICredentialsByHost" ascii //weight: 1
        $x_1_6 = "smtp.live.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

