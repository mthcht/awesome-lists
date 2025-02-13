rule Trojan_Win32_Nachhat_A_2147621190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nachhat.A"
        threat_id = "2147621190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nachhat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Microcoft Corporation. All rights reserved" wide //weight: 10
        $x_1_2 = "with our actions and" ascii //weight: 1
        $x_1_3 = "live it, or live with it." ascii //weight: 1
        $x_1_4 = "system32\\drivers" ascii //weight: 1
        $x_1_5 = "ERROR_IN_PARAMS_ID" ascii //weight: 1
        $x_1_6 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_7 = "rvz1=%d&rvz2=%.10u" ascii //weight: 1
        $x_1_8 = "outpost.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

