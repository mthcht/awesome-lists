rule Trojan_Win32_Bolik_A_2147750445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bolik.A!MTB"
        threat_id = "2147750445"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bolik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff 36 8b 14 24 83 c4 04 31 ca 01 c2 81 ea ?? ?? ?? ?? 31 c2 c1 ca 06 29 c2 c1 c2 16 89 16 83 c6 04 83 e9 04 83 f9 00 77}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 1e c1 cb 08 01 cb 01 cb 81 eb ?? ?? ?? ?? 01 fb 29 cb 81 e9 04 00 00 00 29 fb 89 1e 81 c6 04 00 00 00 81 f9 00 00 00 00 77}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

