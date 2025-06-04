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

rule Ransom_Win64_Gunra_A_2147941953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Gunra.A"
        threat_id = "2147941953"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Gunra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2e 00 45 00 4e 00 43 00 52 00 54 00 00 00}  //weight: 5, accuracy: High
        $x_5_2 = {73 00 74 00 6f 00 70 00 6d 00 61 00 72 00 6b 00 65 00 72 00 00 00}  //weight: 5, accuracy: High
        $x_1_3 = "But you have not so enough time" ascii //weight: 1
        $x_1_4 = "YOUR ALL DATA HAVE BEEN ENCRYPTED!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win64_Gunra_PA_2147942739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Gunra.PA!MTB"
        threat_id = "2147942739"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Gunra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".ENCRT" wide //weight: 1
        $x_1_2 = "!!!DANGER !!!" ascii //weight: 1
        $x_2_3 = "YOUR ALL DATA HAVE BEEN ENCRYPTED!" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

