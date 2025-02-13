rule Trojan_Win32_Fakemsn_I_2147653187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fakemsn.I"
        threat_id = "2147653187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakemsn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Msn Hacker" ascii //weight: 1
        $x_1_2 = "\\windows Live\\Messenger\\msn1.exe" ascii //weight: 1
        $x_3_3 = "www.invasaohacking.com" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

