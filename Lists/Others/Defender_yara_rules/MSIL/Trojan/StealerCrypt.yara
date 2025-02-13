rule Trojan_MSIL_StealerCrypt_MC_2147914534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerCrypt.MC!MTB"
        threat_id = "2147914534"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 d6 72 00 70 28 5f 00 00 2b 80 f7 07 00 04 20 07 00 00 00 38 5b ff ff ff 72 72 72 00 70 72 fa 72 00 70 28 60 00 00 2b 80 f2 07 00 04 20 03 00 00 00 38 3d ff ff ff 72 1c 73 00 70 72 28 73 00 70 28 61 00 00 2b 80 f8 07 00 04 20 06 00 00 00 38 1f ff ff ff 72 72 72 00 70 72 52 73 00 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

