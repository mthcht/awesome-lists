rule Trojan_Win32_Prewat_A_2147627749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Prewat.A"
        threat_id = "2147627749"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Prewat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reward.RewardPot.co.kr" ascii //weight: 1
        $x_1_2 = "version=%s&code=%s&mac=%s&oldversion=%s" ascii //weight: 1
        $x_1_3 = "file0=RewardPot." ascii //weight: 1
        $x_1_4 = "[TerminateProcess]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

