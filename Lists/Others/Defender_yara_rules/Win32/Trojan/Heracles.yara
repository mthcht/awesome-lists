rule Trojan_Win32_Heracles_ARAX_2147945321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Heracles.ARAX!MTB"
        threat_id = "2147945321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$07cac049-a238-45f2-9196-0dbf1c49295b" ascii //weight: 2
        $x_2_2 = "svchost.Login.resources" ascii //weight: 2
        $x_2_3 = "svchost.svchost.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

