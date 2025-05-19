rule Ransom_Win64_Gunra_SACR_2147941718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Gunra.SACR!MTB"
        threat_id = "2147941718"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Gunra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "!!!DANGER !!!" ascii //weight: 2
        $x_1_2 = "DO NOT MODIFY or try to RECOVER any files yourself.We WILL NOT be able to RESTORE them." ascii //weight: 1
        $x_1_3 = "YOUR ALL DATA HAVE BEEN ENCRYPTED!" ascii //weight: 1
        $x_1_4 = "You can decrypt some of your files for free when you contact us" ascii //weight: 1
        $x_1_5 = "R3ADM3.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

