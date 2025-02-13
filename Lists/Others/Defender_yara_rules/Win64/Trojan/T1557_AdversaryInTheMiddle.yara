rule Trojan_Win64_T1557_AdversaryInTheMiddle_A_2147846085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/T1557_AdversaryInTheMiddle.A"
        threat_id = "2147846085"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "T1557_AdversaryInTheMiddle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sekurlsa::pth" wide //weight: 10
        $x_10_2 = "misc::efs" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

