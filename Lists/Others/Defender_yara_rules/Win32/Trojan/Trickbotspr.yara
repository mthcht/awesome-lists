rule Trojan_Win32_Trickbotspr_A_2147766712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbotspr.A!mod"
        threat_id = "2147766712"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbotspr"
        severity = "Critical"
        info = "mod: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CmainSpreader::init() CreateThread, error code %i" ascii //weight: 1
        $x_1_2 = "CmainSpreader::init() CreateEvent, error code %i" ascii //weight: 1
        $x_1_3 = "WormShare" ascii //weight: 1
        $x_1_4 = "lsass.exe" ascii //weight: 1
        $x_1_5 = "End of Romance" ascii //weight: 1
        $x_1_6 = "spreader with module handle 0x%08X is started" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

