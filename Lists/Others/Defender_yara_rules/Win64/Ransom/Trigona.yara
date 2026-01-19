rule Ransom_Win64_Trigona_YAA_2147904059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Trigona.YAA!MTB"
        threat_id = "2147904059"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Trigona"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 45 30 48 2b 45 38 48 89 45 38 48 0f b6 45 38 88 45 2f 48 0f b6 45 2f 30 03 83 ee 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Trigona_MX_2147960353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Trigona.MX!MTB"
        threat_id = "2147960353"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Trigona"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Try to encrypt file" wide //weight: 1
        $x_1_2 = "Get computer ID" wide //weight: 1
        $x_1_3 = "/stealth" wide //weight: 1
        $x_1_4 = "Encryption completed." wide //weight: 1
        $x_1_5 = "OnePathEncryption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win64_Trigona_YBG_2147961294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Trigona.YBG!MTB"
        threat_id = "2147961294"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Trigona"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Encryption completed" wide //weight: 3
        $x_1_2 = "/wipepath" wide //weight: 1
        $x_1_3 = "Prepare TXT" wide //weight: 1
        $x_1_4 = "/-prerename" wide //weight: 1
        $x_1_5 = "/stealth option can't be used without /p option " wide //weight: 1
        $x_1_6 = "/sym_path" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

