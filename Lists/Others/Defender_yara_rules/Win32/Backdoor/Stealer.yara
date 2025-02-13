rule Backdoor_Win32_Stealer_A_2147743716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Stealer.A!MSR"
        threat_id = "2147743716"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f be c0 33 c1 88 84 0a 00 0f be [0-8] [0-10] 42 83 fa ?? 72}  //weight: 5, accuracy: Low
        $x_1_2 = "%sd.e%sc \"%s > %s 2>&1\"" wide //weight: 1
        $x_1_3 = "Request/%lu" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

