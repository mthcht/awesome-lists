rule Trojan_Win32_Backboot_CA_2147815822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Backboot.CA!MTB"
        threat_id = "2147815822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Backboot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 45 b5 80 c6 45 b6 89 c6 45 b7 8b c6 45 b8 8c c6 45 b9 78 c6 45 ba 83 c6 45 bb 58 c6 45 bc 83 c6 45 bd 83 c6 45 be 86 c6 45 bf 7a c6 45 c0 5c c6 45 c1 8f c6 45 c2 65 c6 45 c3 8c c6 45 c4 84 c6 45 c5 78}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

