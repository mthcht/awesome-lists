rule PWS_Win32_Graftor_S_2147744213_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Graftor.S!MSR"
        threat_id = "2147744213"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aHR0cDovL2hheDR0b29scy5jb20vU2F2ZUZvcndhcmRlci9zYXZlLnBocA==" ascii //weight: 1
        $x_1_2 = "/html-sandboxed" wide //weight: 1
        $x_1_3 = "CHANGE_PASSWORD" ascii //weight: 1
        $x_1_4 = "saUsername" ascii //weight: 1
        $x_1_5 = "CookieCollection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

