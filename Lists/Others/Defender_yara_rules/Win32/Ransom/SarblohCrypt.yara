rule Ransom_Win32_SarblohCrypt_PA_2147776834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SarblohCrypt.PA!MTB"
        threat_id = "2147776834"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SarblohCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\Desktop\\README_SARBLOH.txt" wide //weight: 3
        $x_1_2 = "sarbloh" wide //weight: 1
        $x_1_3 = "YOUR FILES ARE LOCKED!" wide //weight: 1
        $x_1_4 = "YOUR FILES ARE GONE!!!" wide //weight: 1
        $x_3_5 = "FUCKINDIA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

