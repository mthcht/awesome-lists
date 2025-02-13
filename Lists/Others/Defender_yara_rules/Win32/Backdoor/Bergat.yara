rule Backdoor_Win32_Bergat_A_2147688198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bergat.A"
        threat_id = "2147688198"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bergat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FakeMessage" wide //weight: 1
        $x_1_2 = "CYBERGATEPASS" wide //weight: 1
        $x_1_3 = "CyberGateKeylogger" wide //weight: 1
        $x_1_4 = "[Execute]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

