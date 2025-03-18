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

rule Trojan_Win64_Gomal_A_2147936268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Gomal.A!MTB"
        threat_id = "2147936268"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Gomal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 3b 66 10 0f 86 ?? 00 00 00 55 48 89 e5 48 83 ec 40 48 89 44 24 50 48 89 c3 48 89 d9 48 8d 05 7c 0e 01 00 e8 97 39 f6 ff 48 89 44 24 28 48 8b 5c 24 50 48 89 d9 e8 c5 0e fc ff ?? ?? ?? ?? ?? 48 85 db 74 36}  //weight: 2, accuracy: Low
        $x_2_2 = {49 3b 66 10 0f 86 c2 00 00 00 55 48 89 e5 48 83 ec 50 66 44 0f d6 7c 24 48 48 89 5c 24 68 48 89 44 24 60 c6 44 24 37 00 b9 31 00 00 00 bf 06 00 02 00 b8 01 00 00 80 48 8d 1d 0b b6 04 00 66 ?? e8 5b d6 ff ff 48 85 db 75 70}  //weight: 2, accuracy: Low
        $x_1_3 = "Go build ID: \"DhPRtKn3hDGs3liDAHCt/mVWqbG9z8gcfbRGurp93/jH8zxIc3AW_yYMuHKeR3/sQcifcJTnr5trfae70Cp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

