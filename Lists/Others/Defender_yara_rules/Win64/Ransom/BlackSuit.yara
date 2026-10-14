rule Ransom_Win64_BlackSuit_VV_2147980176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BlackSuit.VV!MTB"
        threat_id = "2147980176"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackSuit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Extortioner named BlackSuit has attacked your system." ascii //weight: 1
        $x_1_2 = "FUCKED_BY_THELORD" ascii //weight: 1
        $x_1_3 = "To decrypt your files you have to pay a ransom." ascii //weight: 1
        $x_1_4 = "PAY THE RANSOM OR YOUR DATA STAYS BROKEN" ascii //weight: 1
        $x_1_5 = ".blacksuit" ascii //weight: 1
        $x_1_6 = "C:\\BlackSuitBoot" ascii //weight: 1
        $x_1_7 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\BlackSuit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

