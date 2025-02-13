rule DoS_Win32_Dhos_A_2147655301_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/Dhos.A"
        threat_id = "2147655301"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dhos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attack" ascii //weight: 1
        $x_1_2 = "hacker" ascii //weight: 1
        $x_1_3 = "thc-ssl-dos" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

