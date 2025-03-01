rule Trojan_Linux_DnsAmp_B_2147819516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/DnsAmp.B!xp"
        threat_id = "2147819516"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "DnsAmp"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DNS_Flood" ascii //weight: 1
        $x_1_2 = {00 20 af b1 00 1c af b0 00 18 af bc 00 10 8f 91 80 1c 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "gethostbyname" ascii //weight: 1
        $x_1_4 = {14 24 84 a0 00 10 40 00 05 24 a5 07 b4 03 20 f8 09 00}  //weight: 1, accuracy: High
        $x_1_5 = "DealwithDDoS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

