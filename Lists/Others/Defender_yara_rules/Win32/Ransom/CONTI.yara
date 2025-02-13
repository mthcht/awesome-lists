rule Ransom_Win32_CONTI_DA_2147768354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CONTI.DA!MTB"
        threat_id = "2147768354"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CONTI"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All of your files are currently encrypted by CONTI strain" ascii //weight: 1
        $x_1_2 = "YOU SHOULD BE AWARE!" ascii //weight: 1
        $x_1_3 = ".onion" ascii //weight: 1
        $x_1_4 = "https://contirecovery.info" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_CONTI_DC_2147771290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CONTI.DC!MTB"
        threat_id = "2147771290"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CONTI"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "contirecovery" ascii //weight: 1
        $x_1_2 = "YOU SHOULD BE AWARE!" ascii //weight: 1
        $x_1_3 = ".onion" ascii //weight: 1
        $x_1_4 = "---BEGIN ID---" ascii //weight: 1
        $x_1_5 = "TOR VERSION :" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

