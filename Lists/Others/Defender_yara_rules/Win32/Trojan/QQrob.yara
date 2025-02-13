rule Trojan_Win32_QQrob_RPY_2147848434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QQrob.RPY!MTB"
        threat_id = "2147848434"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QQrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e1 02 0b c1 88 45 df 0f b6 55 df f7 d2 88 55 df 0f b6 45 df 03 45 e0 88 45 df 0f b6 4d df c1 f9 03 0f b6 55 df c1 e2 05 0b ca 88 4d df 0f b6 45 df 83 c0 70 88 45 df 0f b6 4d df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

