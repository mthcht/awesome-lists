rule Trojan_Win32_MetaStealer_AT_2147922307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MetaStealer.AT!MTB"
        threat_id = "2147922307"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MetaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TaskManager@stealer" ascii //weight: 1
        $x_1_2 = "rat\\client\\stealer" ascii //weight: 1
        $x_1_3 = "Listen@" ascii //weight: 1
        $x_1_4 = "$allocator@" ascii //weight: 1
        $x_1_5 = "stealertest.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

