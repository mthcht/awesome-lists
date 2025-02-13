rule Trojan_MSIL_Walgentz_Z_2147923454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Walgentz.Z!MTB"
        threat_id = "2147923454"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Walgentz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/api.php" ascii //weight: 1
        $x_1_2 = "/api-debug.php" ascii //weight: 1
        $x_1_3 = "?status=1&wallets=" ascii //weight: 1
        $x_1_4 = "?status=2&wallets=" ascii //weight: 1
        $x_1_5 = "DownloadString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

