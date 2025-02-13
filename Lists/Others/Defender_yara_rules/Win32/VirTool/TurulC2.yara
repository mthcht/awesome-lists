rule VirTool_Win32_TurulC2_A_2147897137_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/TurulC2.A!sms"
        threat_id = "2147897137"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "TurulC2"
        severity = "Critical"
        info = "sms: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AgentDelay" ascii //weight: 1
        $x_1_2 = "AgentJitter" ascii //weight: 1
        $x_1_3 = "KillDate" ascii //weight: 1
        $x_1_4 = "WorkingHours" ascii //weight: 1
        $x_1_5 = "Profile" ascii //weight: 1
        $x_1_6 = "c2hhcnBzbmlwZXI=" ascii //weight: 1
        $x_1_7 = "c2hhcnBkb21haW5zcHJheQ=" ascii //weight: 1
        $x_1_8 = "c2hhcnB2aWV3" ascii //weight: 1
        $x_1_9 = "TW9kdWxlIGhhcyBiZWVuIGRlcGxveWVkIQ=" ascii //weight: 1
        $x_1_10 = "UmVhZHkgYW5kIHdhaXRpbmcgZm9yIGEgY29tbWFuZA=" ascii //weight: 1
        $x_1_11 = "aHR0c" ascii //weight: 1
        $x_1_12 = "U3dpdGNoaW5nIHRvIHdz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

