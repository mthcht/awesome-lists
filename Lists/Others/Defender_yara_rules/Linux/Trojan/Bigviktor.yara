rule Trojan_Linux_Bigviktor_A_2147760033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Bigviktor.A!MTB"
        threat_id = "2147760033"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Bigviktor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ftp@example.com" ascii //weight: 1
        $x_1_2 = "%s/s.jpeg" ascii //weight: 1
        $x_1_3 = "/male.jpeg" ascii //weight: 1
        $x_1_4 = "%s/image.jpeg?t=%c%c%c%c%c%c%c%c&v=%d" ascii //weight: 1
        $x_1_5 = "1.1.1.1,8.8.8.8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

