rule Trojan_Win32_EvasionViaPathExclusion_AD_2147941896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EvasionViaPathExclusion.AD"
        threat_id = "2147941896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EvasionViaPathExclusion"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "powershell.exe add-mppreference -exclusionpath %temp%\\aiq" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

