rule Trojan_Win32_AttackServerCloudBlockTest_A_2147915640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AttackServerCloudBlockTest.A"
        threat_id = "2147915640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AttackServerCloudBlockTest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\powershell.exe " wide //weight: 1
        $x_1_2 = "04be58b4-64b3-47d4-9fa7-d15ee1725a49" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

