rule Trojan_Win32_SuspNextJsRscDeserRce_A_2147971122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspNextJsRscDeserRce.A!sms"
        threat_id = "2147971122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspNextJsRscDeserRce"
        severity = "Critical"
        info = "sms: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "__proto__:then" ascii //weight: 1
        $x_1_2 = "constructor:constructor" ascii //weight: 1
        $x_1_3 = "resolved_model" ascii //weight: 1
        $x_1_4 = "_response" ascii //weight: 1
        $x_1_5 = "_formData" ascii //weight: 1
        $x_1_6 = "NEXT_REDIRECT" ascii //weight: 1
        $x_1_7 = "child_process" ascii //weight: 1
        $x_1_8 = "execSync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

