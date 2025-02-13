rule Trojan_Win32_Phrewhid_A_2147685569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phrewhid.A"
        threat_id = "2147685569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phrewhid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 d2 33 55 f4 88 17 46 47 8b 55 fc 85 d2 74 05 83 ea 04 8b 12}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e1 09 0f b7 58 f2 c1 eb 07 66 33 cb 66 89 48 0e eb 3f}  //weight: 1, accuracy: High
        $x_1_3 = "rew.php?hwid=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

