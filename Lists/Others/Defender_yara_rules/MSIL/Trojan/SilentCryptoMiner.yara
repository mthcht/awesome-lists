rule Trojan_MSIL_SilentCryptoMiner_2147893045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SilentCryptoMiner!rootkit"
        threat_id = "2147893045"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SilentCryptoMiner"
        severity = "Critical"
        info = "rootkit: rootkit component of that malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 0b 11 0a 11 06 28 10 00 00 06 26 11 0a 11 06 07 6a 20 00 30 00 00 1f 40 28 0e 00 00 06 26 11 0a 11 06 02 08 16 6a 28 0f 00 00 06 26 16}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SilentCryptoMiner_NR_2147929305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SilentCryptoMiner.NR!MTB"
        threat_id = "2147929305"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SilentCryptoMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {03 28 58 00 00 0a 28 59 00 00 0a 13 00 20 01 00 00 00 7e 17 02 00 04 7b 2c 02 00 04 3a c9 ff ff ff 26 20 00 00 00 00 38 be ff ff ff 2a}  //weight: 3, accuracy: High
        $x_2_2 = {13 01 20 0b 00 00 00 38 d5 fe ff ff 28 54 00 00 0a 03 6f 55 00 00 0a 13 03 20 0c 00 00 00 38 be fe ff ff}  //weight: 2, accuracy: High
        $x_1_3 = "Reoxggyzhux.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

