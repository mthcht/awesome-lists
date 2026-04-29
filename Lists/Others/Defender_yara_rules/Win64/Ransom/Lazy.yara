rule Ransom_Win64_Lazy_LRI_2147967773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Lazy.LRI!MTB"
        threat_id = "2147967773"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ooops, your files have been encrypted!" ascii //weight: 1
        $x_2_2 = "Your important files are encrypted." ascii //weight: 2
        $x_3_3 = "TermedRansom" ascii //weight: 3
        $x_4_4 = "termed.lol" ascii //weight: 4
        $x_5_5 = "Google Chromekey1" ascii //weight: 5
        $x_6_6 = "lsass.exe" ascii //weight: 6
        $x_7_7 = "Discord Token Tool/1.0" ascii //weight: 7
        $x_8_8 = "To decrypt your files, contact us on Discord:" ascii //weight: 8
        $x_9_9 = "are no longer accessible because they have been encrypted." ascii //weight: 9
        $x_10_10 = "Your files are encrypted!" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Lazy_LRJ_2147967951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Lazy.LRJ!MTB"
        threat_id = "2147967951"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".encrypt" ascii //weight: 1
        $x_2_2 = "Your files have been encrypted and your personal information has been collected." ascii //weight: 2
        $x_3_3 = "stealer-go" ascii //weight: 3
        $x_4_4 = ".del_system32" ascii //weight: 4
        $x_5_5 = ".overwrite_user_data" ascii //weight: 5
        $x_6_6 = ".corrupt_registry" ascii //weight: 6
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

