rule Trojan_Win32_PurelogsStealer_ST_2147978266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PurelogsStealer.ST!MTB"
        threat_id = "2147978266"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PurelogsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 f7 35 10 70 21 03 8a 82 00 70 21 03 30 81 18 70 21 03 41 3b ce 72 e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

