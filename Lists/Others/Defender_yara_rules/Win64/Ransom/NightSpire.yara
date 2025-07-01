rule Ransom_Win64_NightSpire_BA_2147944525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/NightSpire.BA!MTB"
        threat_id = "2147944525"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "NightSpire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your sensetive data are stolen and encrypted!" ascii //weight: 1
        $x_1_2 = "After that we will public this situation and all data." ascii //weight: 1
        $x_1_3 = "DO NOT MODIFY FILES YOURSELF." ascii //weight: 1
        $x_1_4 = "DO NOT USE THIRD PARTY SOFTWARE TO RESTORE YOUR DATA." ascii //weight: 1
        $x_1_5 = "onionmail.org" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_NightSpire_YAF_2147945133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/NightSpire.YAF!MTB"
        threat_id = "2147945133"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "NightSpire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encrypted by NightSpire Ransomware" ascii //weight: 1
        $x_1_2 = "decryption key" ascii //weight: 1
        $x_1_3 = "use third-party software" ascii //weight: 1
        $x_1_4 = "databases are stolen" ascii //weight: 1
        $x_1_5 = "Go build ID:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

