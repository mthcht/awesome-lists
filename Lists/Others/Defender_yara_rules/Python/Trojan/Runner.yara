rule Trojan_Python_Runner_RRI_2147966702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Python/Runner.RRI!MTB"
        threat_id = "2147966702"
        type = "Trojan"
        platform = "Python: Python scripts"
        family = "Runner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 66 70 74 61 62 6c 65 00 01 00 00 00 b0 04 00 00 02 00 00 00 3a 04 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 72 73 72 63 00 00 00 70 05 00 00 00 c0 04 00 00 06 00 00 00 3c 04 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

