rule Trojan_AndroidOS_Bray_C_2147809958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Bray.C!MTB"
        threat_id = "2147809958"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Bray"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HBAPBQgJOBcKFw=" ascii //weight: 1
        $x_1_2 = "AxQPCwIDCRAGBwc=" ascii //weight: 1
        $x_1_3 = "AxQPCzIBFCYeMxYSAg4MCgkTRFpE" ascii //weight: 1
        $x_1_4 = "AwE+CwQaDgcCOwYeGBAaBDMOAA==" ascii //weight: 1
        $x_1_5 = "AwE+CBEzBgcECwYeBQ==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

