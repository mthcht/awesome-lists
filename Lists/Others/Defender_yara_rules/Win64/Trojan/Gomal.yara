rule Trojan_Win64_Gomal_RF_2147888660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Gomal.RF!MTB"
        threat_id = "2147888660"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Gomal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID: \"UMA1wM_Wdj3A9fKWeR6Z/4bWD3Ln6adTvHFTlG5Vw/lLkBJiDDxztvDB9ckfUA/R45rDk8tTDZd0bSoL1ho" ascii //weight: 1
        $x_1_2 = "Go build ID: \"DGOF_U0-KA13DkK_k-bg/eB6gwb3DfThBy4Scd8ZP/c3tw-SozJi5L3vU_Y0jt/fFUPoXwacRQZAt2OoG6Z" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

