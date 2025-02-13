rule Trojan_Win32_Sumber_A_2147742763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sumber.A!dha"
        threat_id = "2147742763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sumber"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "SMB_FOR_ALL_Ultimate" ascii //weight: 3
        $x_2_2 = "Command format  %s TargetIp domainname" ascii //weight: 2
        $x_1_3 = "Construct ConsTransSecondary" ascii //weight: 1
        $x_1_4 = "create pipe twice failed." ascii //weight: 1
        $x_1_5 = "Construct NTCreateAndXRequest  Failed." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

