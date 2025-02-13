rule Trojan_Win32_KRBanker_A_2147723847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KRBanker.A"
        threat_id = "2147723847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KRBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "safebank.korea.co.kr" ascii //weight: 1
        $x_1_2 = "AYAgent.aye" ascii //weight: 1
        $x_1_3 = "BlackMoon RunTime Error:" ascii //weight: 1
        $x_1_4 = "?=deleted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

