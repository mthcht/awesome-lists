rule Trojan_Win32_ProcessHijack_PA_2147743874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProcessHijack.PA!MTB"
        threat_id = "2147743874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcessHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 be f9 ff ff f7 d1 e8 00 00 00 00 5b 83 c3 11 93 ba 8f 3f 5d 1a 31 10 83 c0 04 e2 f9}  //weight: 1, accuracy: High
        $x_1_2 = {b9 41 06 00 00 e8 00 00 00 00 5b 83 c3 10 93 81 30 6b af 89 1d 83 c0 04 e2 f5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

