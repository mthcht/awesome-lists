rule Trojan_Win32_CeeInject_DEA_2147760003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CeeInject.DEA!MTB"
        threat_id = "2147760003"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 bb 1e 00 00 99 b9 bb 1e 00 00 f7 f9 33 d2 8a 94 05 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 25 ff 00 00 00 33 d0 8b 4d fc 88 94 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

