rule Trojan_Win32_Reapta_A_2147655960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reapta.A"
        threat_id = "2147655960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reapta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".*name=\"captcha\"" ascii //weight: 1
        $x_1_2 = "value=\"([^\"]*)\".*" ascii //weight: 1
        $x_1_3 = {26 67 5f 73 69 64 3d 00 63 61 70 74 63 68 61 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

