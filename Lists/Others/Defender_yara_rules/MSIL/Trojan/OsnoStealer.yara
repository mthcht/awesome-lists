rule Trojan_MSIL_OsnoStealer_RDA_2147849149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/OsnoStealer.RDA!MTB"
        threat_id = "2147849149"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "OsnoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6a89fec8-355c-4408-8215-bffbc3c98940" ascii //weight: 1
        $x_1_2 = "Cracked Venom Rootkit" ascii //weight: 1
        $x_1_3 = "DeploymentMetadata" ascii //weight: 1
        $x_1_4 = "LKNFqwdMCkIQsFChqlckaMIDyBCn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

