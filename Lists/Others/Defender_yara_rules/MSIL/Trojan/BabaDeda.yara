rule Trojan_MSIL_BabaDeda_NEAA_2147838272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BabaDeda.NEAA!MTB"
        threat_id = "2147838272"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BabaDeda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "e3fd117e-b2c4-4f02-a48f-4b6633275f2a" ascii //weight: 10
        $x_2_2 = "Orion" ascii //weight: 2
        $x_2_3 = "Org.BouncyCastle.Crypto.Engines" ascii //weight: 2
        $x_2_4 = "deactivation.php" wide //weight: 2
        $x_2_5 = "/dev/disk/by-uuid" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

