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
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\System Volume Information\\FsTx\\95F62703B343F111A92A005056975458\\FsTxLogs\\FsTxLog.blf" ascii //weight: 10
        $x_10_2 = "C:\\System Volume Information\\FsTx\\95F62703B343F111A92A005056975458\\FsTxLogs\\FsTxKtmLog.blf" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

