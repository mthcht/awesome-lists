rule Trojan_MSIL_CryptoObf_CI_2147942498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptoObf.CI!MTB"
        threat_id = "2147942498"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoObf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {70 0a 06 28 ?? 00 00 0a 25 26 0b 28 4b 00 00 0a [0-2] 07 16 07 8e 69 6f 4c 00 00 0a 25 26 0a 28 ?? 00 00 0a 25 26 06 6f ?? 00 00 0a [0-3] 0c 1f 61 6a 08 28 27 00 00 06 25 26 80 08 00 00 04}  //weight: 2, accuracy: Low
        $x_1_2 = "MaliciousProgram" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

