rule Trojan_Win32_FraudPack_BB_2147823621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FraudPack.BB!MTB"
        threat_id = "2147823621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FraudPack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f7 d2 42 2b c2 4a f7 d2 36 3e 74}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

