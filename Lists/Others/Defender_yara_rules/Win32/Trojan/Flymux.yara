rule Trojan_Win32_Flymux_A_2147631107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Flymux.A"
        threat_id = "2147631107"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Flymux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 69 6e 64 20 66 6c 79 20 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = "C4560D12-CE25-4A2E-A5D4-B5070FCBE282" ascii //weight: 1
        $x_1_3 = {64 6c 6c 6d 75 78 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

