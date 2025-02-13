rule Trojan_Win32_Malgentz_AT_2147920880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Malgentz.AT!MTB"
        threat_id = "2147920880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Malgentz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 81 c2 3b 03 00 00 81 e2 84 0c 01 00 81 c2 e8 06 00 00 5a 56 53 83 c4 04 81 ce 48 78 00 00 81 c6 0b 09 01 00 81 f6 04 e1 00 00 81 ce 41 01 01 00 5e 69 95 20 ed ff ff fe 00 00 00 81 c2 3b 66 f3 56 69 85 20 ed ff ff fe 00 00 00 2b d0 81 f2 72 62 aa 00 0f af 95 20 ed ff ff 69 8d 20 ed ff ff fe 00 00 00 2b d1 89 95 1c ed ff ff 53 81 c3 c8 c1 00 00 81 cb db 0a 01 00 5b 56 52 83 c4 04 81 ce ab c1 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 81 ec b8 27 00 00 53 56 57 53 81 cb 80 33 01 00 81 eb 67 64 00 00 81 c3 1a 22 01 00 5b 50 57 83 c4 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

