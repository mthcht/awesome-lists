rule Backdoor_Win64_Swoorp_A_2147709048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Swoorp.A"
        threat_id = "2147709048"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Swoorp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "s00perp4ssw0rd" ascii //weight: 1
        $x_1_2 = "p4ssw0rd" ascii //weight: 1
        $x_1_3 = "StartJavaScript=" ascii //weight: 1
        $x_1_4 = "/cgi-bin/s2.cgi" ascii //weight: 1
        $x_1_5 = "Cannot download:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

