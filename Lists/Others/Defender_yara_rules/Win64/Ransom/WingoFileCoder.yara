rule Ransom_Win64_WingoFileCoder_ARA_2147951015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/WingoFileCoder.ARA!MTB"
        threat_id = "2147951015"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "WingoFileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "files have been encrypted by DarkLulz Ransomware" ascii //weight: 2
        $x_2_2 = "darklulz@onionmail.org" ascii //weight: 2
        $x_2_3 = "To recover your files, you must pay" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

