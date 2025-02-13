rule Ransom_Win32_FancyLocker_PAB_2147788146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FancyLocker.PAB!MTB"
        threat_id = "2147788146"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FancyLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files have been encrypted!" wide //weight: 1
        $x_1_2 = "infected with FancyLocker" ascii //weight: 1
        $x_1_3 = "data will get leaked!" ascii //weight: 1
        $x_1_4 = "dropRansomLetter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

