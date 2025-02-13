rule Trojan_MSIL_XShark_A_2147745256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XShark.A!MTB"
        threat_id = "2147745256"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XShark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XSharked000" ascii //weight: 1
        $x_1_2 = "/command.bin" ascii //weight: 1
        $x_1_3 = "/result.bin" ascii //weight: 1
        $x_1_4 = "/userInfo.php" ascii //weight: 1
        $x_1_5 = "ServerXShark" ascii //weight: 1
        $x_1_6 = "StubXShark" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

