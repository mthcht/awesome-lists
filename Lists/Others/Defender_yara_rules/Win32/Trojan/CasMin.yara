rule Trojan_Win32_CasMin_2147741808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CasMin!MTB"
        threat_id = "2147741808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CasMin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "libgcj-13.dll" ascii //weight: 1
        $x_1_2 = "_Jv_RegisterClasses" ascii //weight: 1
        $x_1_3 = "%%glue:L" ascii //weight: 1
        $x_1_4 = "bit32" ascii //weight: 1
        $x_1_5 = "srlua" ascii //weight: 1
        $x_1_6 = "tmpnam" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

