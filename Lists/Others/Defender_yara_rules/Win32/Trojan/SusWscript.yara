rule Trojan_Win32_SusWscript_MK_2147945913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusWscript.MK"
        threat_id = "2147945913"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusWscript"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wscript" wide //weight: 1
        $x_1_2 = "appdata\\local\\temp" wide //weight: 1
        $x_1_3 = "bdata.vbs //b" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

