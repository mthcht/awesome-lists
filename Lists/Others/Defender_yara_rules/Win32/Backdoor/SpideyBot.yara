rule Backdoor_Win32_SpideyBot_AR_2147744220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/SpideyBot.AR!MSR"
        threat_id = "2147744220"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "SpideyBot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {44 3a 5c 50 72 6f 6a 65 63 74 73 5c 46 75 63 6b 20 4f 66 66 ?? ?? ?? 5c 52 65 6c 65 61 73 65 5c 46 75 63 6b 20 4f 66 66 ?? ?? ?? 2e 70 64 62}  //weight: 3, accuracy: Low
        $x_1_2 = "bW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKCcuL2NvcmUuYXNhcicpOw==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

