rule Trojan_Win64_CryptoClipper_A_2147842340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CryptoClipper.A!MTB"
        threat_id = "2147842340"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CryptoClipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "crypto-clipper/main.go" ascii //weight: 2
        $x_2_2 = "clipboard.go" ascii //weight: 2
        $x_2_3 = "clipboard_windows.go" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

