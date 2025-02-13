rule Worm_MSIL_Smpdoss_A_2147684256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Smpdoss.A"
        threat_id = "2147684256"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Smpdoss"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smpbot" wide //weight: 1
        $x_1_2 = "CONNECTED|" wide //weight: 1
        $x_1_3 = "UDP Flooding" wide //weight: 1
        $x_1_4 = "STATUS|SSYN Attacking" wide //weight: 1
        $x_1_5 = "KLOG|" wide //weight: 1
        $x_1_6 = "Attemping to seed" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

