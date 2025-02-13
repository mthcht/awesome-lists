rule Trojan_MSIL_AurusCrypt_A_2147836644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AurusCrypt.A!MTB"
        threat_id = "2147836644"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AurusCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 09 08 5d 6f ?? 00 00 0a 6f ?? 00 00 0a 61 d2 9c 09 17 58 0d 09 07 8e 69 3f}  //weight: 2, accuracy: Low
        $x_1_2 = "GetDomain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

