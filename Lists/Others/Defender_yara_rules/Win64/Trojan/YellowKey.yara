rule Trojan_Win64_YellowKey_DA_2147969247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/YellowKey.DA!MTB"
        threat_id = "2147969247"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "YellowKey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "95F62703B343F111A92A005056975458" ascii //weight: 10
        $x_1_2 = "FsTxKtmLog" ascii //weight: 1
        $x_1_3 = "FsTxLog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

