rule Trojan_Win32_RTMBanker_MR_2147753535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RTMBanker.MR!MTB"
        threat_id = "2147753535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RTMBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 f6 2b 37 f7 de 83 ef ?? 83 ee ?? c1 ce ?? 29 d6 83 ee ?? 29 d2 29 f2 f7 da c1 c2 ?? d1 ca ?? ?? 8f 01 01 31 83 e9 ?? 83 eb ?? 8d 5b ?? 83 fb ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

