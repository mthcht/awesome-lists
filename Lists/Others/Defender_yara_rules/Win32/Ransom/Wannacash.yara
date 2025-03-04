rule Ransom_Win32_WannaCash_SK_2147755745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCash.SK!MTB"
        threat_id = "2147755745"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCash"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "clubnika@cock.li] .WANNACASH NCOV" wide //weight: 1
        $x_1_2 = "omguni:[" wide //weight: 1
        $x_1_3 = "RSA1024:" wide //weight: 1
        $x_1_4 = "omgdate:[" wide //weight: 1
        $x_1_5 = "omgf:[" wide //weight: 1
        $x_1_6 = "omgp:[" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

