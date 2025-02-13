rule Ransom_Win32_SmertRansom_YAF_2147917663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SmertRansom.YAF!MTB"
        threat_id = "2147917663"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SmertRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--food" ascii //weight: 1
        $x_1_2 = ".smert" ascii //weight: 1
        $x_1_3 = "\\README.txt" ascii //weight: 1
        $x_1_4 = "you got fucked" ascii //weight: 1
        $x_1_5 = "no way to recover the files" ascii //weight: 1
        $x_1_6 = "wuauserv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_SmertRansom_MX_2147919947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SmertRansom.MX!MTB"
        threat_id = "2147919947"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SmertRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ".smert" ascii //weight: 10
        $x_10_2 = "smert.exe" ascii //weight: 10
        $x_1_3 = "cryptsvc" ascii //weight: 1
        $x_1_4 = "wuauserv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

