rule Backdoor_Win32_RaspberryRobin_PA_2147841108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/RaspberryRobin.PA!MTB"
        threat_id = "2147841108"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "RaspberryRobin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac 32 02 aa 42 49 [0-10] 85 c9 80 3a 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

