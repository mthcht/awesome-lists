rule Trojan_Win32_VictoryGate_RDA_2147900740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VictoryGate.RDA!MTB"
        threat_id = "2147900740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VictoryGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "gMqiWKGvl" ascii //weight: 2
        $x_2_2 = "lnoLzHuPw.exe" ascii //weight: 2
        $x_1_3 = "SHELLEXECUTE ( @WORKINGDIR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

