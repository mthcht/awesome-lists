rule Ransom_Win64_Emperor_YBG_2147960021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Emperor.YBG!MTB"
        threat_id = "2147960021"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Emperor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.isRansomNote" ascii //weight: 1
        $x_1_2 = "main.shouldEncrypt" ascii //weight: 1
        $x_1_3 = "main.encryptFile" ascii //weight: 1
        $x_1_4 = "main.encryptDrive" ascii //weight: 1
        $x_1_5 = "main.encryptAllDrives" ascii //weight: 1
        $x_1_6 = "golang" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

