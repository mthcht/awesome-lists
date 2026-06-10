rule Trojan_Win64_CoreFlowBack_A_2147971301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.A"
        threat_id = "2147971301"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "05bbd8d451268a1543ed3209531176954ff235d1b23c98139b24c1220c997dca52" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

