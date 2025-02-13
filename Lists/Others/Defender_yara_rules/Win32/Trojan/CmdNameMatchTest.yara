rule Trojan_Win32_CmdNameMatchTest_A_2147782715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CmdNameMatchTest.A"
        threat_id = "2147782715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CmdNameMatchTest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "a41e8c1b-e4c1-4de6-980a-98484245d6b4" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

