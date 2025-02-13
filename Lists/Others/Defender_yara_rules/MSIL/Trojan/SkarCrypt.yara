rule Trojan_MSIL_SkarCrypt_A_2147844622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SkarCrypt.A!MTB"
        threat_id = "2147844622"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SkarCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 08 11 04 6f ?? 00 00 0a 1f 30 59 6c 23 00 00 00 00 00 00 10 40 1a 11 04 59 17 59 6c 28 ?? 00 00 0a 5a d2 58 d2 0d 11 04 17 59 13 04}  //weight: 2, accuracy: Low
        $x_2_2 = {06 02 11 05 6f ?? 00 00 0a 28 ?? 00 00 0a 11 04 11 05 09 5d 91 1f 30 59 59 d1 6f ?? 00 00 0a 26 11 05 17 58 13 05 11 05 02 6f ?? 00 00 0a 09 59 17 59}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

