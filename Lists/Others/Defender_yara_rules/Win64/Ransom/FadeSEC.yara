rule Ransom_Win64_FadeSEC_AMTB_2147974378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FadeSEC!AMTB"
        threat_id = "2147974378"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FadeSEC"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FadeSEC - SYSTEM LOCKDOWN" ascii //weight: 1
        $x_1_2 = "FadeSEC_README.txt" ascii //weight: 1
        $x_1_3 = ".fadeSEC" ascii //weight: 1
        $x_1_4 = "FadeSEC Recovery Key" ascii //weight: 1
        $x_1_5 = "Ransom notes dropped" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

