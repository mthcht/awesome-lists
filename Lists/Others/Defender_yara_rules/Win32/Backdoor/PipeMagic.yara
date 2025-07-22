rule Backdoor_Win32_PipeMagic_PA_2147947083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PipeMagic.PA!MTB"
        threat_id = "2147947083"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PipeMagic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "fuckit" wide //weight: 1
        $x_3_2 = "\\\\.\\pipe\\1.%s" ascii //weight: 3
        $x_1_3 = {99 b9 ff 00 00 00 f7 f9 88 96 ?? ?? ?? ?? 46 83 fe 10 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

