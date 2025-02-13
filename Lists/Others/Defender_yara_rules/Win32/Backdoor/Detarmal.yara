rule Backdoor_Win32_Detarmal_A_2147643474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Detarmal.A"
        threat_id = "2147643474"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Detarmal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 3b 6d 72 74 64 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {83 f8 46 0f 8f ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? 83 f8 2f 7f ?? 74 ?? 83 e8 28 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

