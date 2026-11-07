rule Trojan_MSIL_BoratRat_AB_2147981706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BoratRat.AB!MTB"
        threat_id = "2147981706"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BoratRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".BoratRat" ascii //weight: 2
        $x_1_2 = "Rans-Status" ascii //weight: 1
        $x_1_3 = "Encryption in progress" ascii //weight: 1
        $x_1_4 = "Already Encrypted!" ascii //weight: 1
        $x_1_5 = "Decryption in progress" ascii //weight: 1
        $x_1_6 = "Already decrypted!" ascii //weight: 1
        $x_1_7 = "READ-ME-NOW.txt" ascii //weight: 1
        $x_1_8 = "Rans-MSG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

