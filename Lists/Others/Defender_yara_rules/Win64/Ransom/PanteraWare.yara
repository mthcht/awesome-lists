rule Ransom_Win64_PanteraWare_C_2147951707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/PanteraWare.C!MTB"
        threat_id = "2147951707"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "PanteraWare"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 14 01 83 f2 ?? 88 14 08 48 ff c1 48 39 cb 7f}  //weight: 10, accuracy: Low
        $x_5_2 = "DeleteShadowCopyAction" ascii //weight: 5
        $x_5_3 = "GetShadowCopyInfoVss" ascii //weight: 5
        $x_5_4 = "SelfDelete" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

