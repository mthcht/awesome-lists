rule PWS_Win32_Kuluoz_A_2147657373_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Kuluoz.gen!A"
        threat_id = "2147657373"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Kuluoz"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 fc 01 6a 15 be 0f 00 00 00 68}  //weight: 1, accuracy: High
        $x_1_2 = "&akk=" ascii //weight: 1
        $x_1_3 = "|(ftps:\\/\\/))?(?<NHost>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

