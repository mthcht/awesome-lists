rule Backdoor_Win32_Netan_A_2147637339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Netan.A"
        threat_id = "2147637339"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Netan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 73 65 72 76 69 63 65 73 2e 65 78 65 00 00 00 00 2e 72 65 6c 6f 63 00}  //weight: 1, accuracy: High
        $x_1_2 = ":443;66.197." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

