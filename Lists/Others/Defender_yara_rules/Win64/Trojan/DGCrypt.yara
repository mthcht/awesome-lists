rule Trojan_Win64_DGCrypt_MCQ_2147962179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DGCrypt.MCQ!MTB"
        threat_id = "2147962179"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DGCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lambda_51387bcbd987f02779c1d1519a231647" ascii //weight: 1
        $x_1_2 = "lambda_9d1d29429b8941eec1e64917398de465" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

