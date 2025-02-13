rule Trojan_Win64_Coinstealer_PAGF_2147929749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coinstealer.PAGF!MTB"
        threat_id = "2147929749"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coinstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SHIT WALLET ADDRESSES:" ascii //weight: 2
        $x_1_2 = "\"data\":{\"address\":\"" ascii //weight: 1
        $x_2_3 = "/Files/Login.php" wide //weight: 2
        $x_1_4 = "&trustwalletFile=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

