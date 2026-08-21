rule Trojan_Win64_LemonStealer_LR_2147976675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LemonStealer.LR!MTB"
        threat_id = "2147976675"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LemonStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LemonStealerno browsers found" ascii //weight: 1
        $x_2_2 = "3injector: payload signaled ready but key length is" ascii //weight: 2
        $x_3_3 = "decode encrypted_key:" ascii //weight: 3
        $x_4_4 = "LemonStealer 0.1.0" ascii //weight: 4
        $x_5_5 = "nd_encrypted_keyapp_bound_encryp," ascii //weight: 5
        $x_6_6 = ".injector: payload did not publish key (marker=" ascii //weight: 6
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

