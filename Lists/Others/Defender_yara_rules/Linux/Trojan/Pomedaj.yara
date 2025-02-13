rule Trojan_Linux_Pomedaj_A_2147752622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Pomedaj.A!MTB"
        threat_id = "2147752622"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Pomedaj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "wget -c pm.ipfswallet.tk/" ascii //weight: 2
        $x_1_2 = "/usr/include/pm.tar.gz" ascii //weight: 1
        $x_2_3 = {b9 10 00 00 00 31 c0 48 89 e7 f3 48 ab 48 89 ea be b0 4f 49 00 48 89 e7 48 89 e3 e8 68 24 00 00 0f 1f 84 00 00 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

