rule Trojan_Win32_Phishbank_A_2147657915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phishbank.A"
        threat_id = "2147657915"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phishbank"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "H-e-l-l-B-o-t" ascii //weight: 1
        $x_1_2 = "start_ddos" ascii //weight: 1
        $x_1_3 = "I_FUCK_DEAD_PPL" ascii //weight: 1
        $x_1_4 = {2f 70 68 69 73 68 00 00 78 6d 61 79 61 62 61 6e 6b 2e 68 74 6d 6c}  //weight: 1, accuracy: High
        $x_1_5 = "%s\\%s\\servicess.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

