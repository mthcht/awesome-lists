rule Trojan_Win64_SlickPlummet_A_2147944831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SlickPlummet.A!dha"
        threat_id = "2147944831"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SlickPlummet"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s:%d:%s(): [+] Overwriting \"%s" ascii //weight: 1
        $x_1_2 = "%s:%d:%s(): [+] Starting RawIo disk driver service.." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

