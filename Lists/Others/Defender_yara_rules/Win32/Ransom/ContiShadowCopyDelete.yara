rule Ransom_Win32_ContiShadowCopyDelete_ZZ_2147806332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiShadowCopyDelete.ZZ"
        threat_id = "2147806332"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiShadowCopyDelete"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe" wide //weight: 1
        $x_1_2 = "WMIC.exe" wide //weight: 1
        $x_1_3 = "where" wide //weight: 1
        $x_1_4 = "ID=" wide //weight: 1
        $x_1_5 = "shadowcopy" wide //weight: 1
        $x_1_6 = "delete" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

