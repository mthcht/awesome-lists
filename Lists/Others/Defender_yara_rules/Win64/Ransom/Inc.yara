rule Ransom_Win64_Inc_BAA_2147944405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Inc.BAA!MTB"
        threat_id = "2147944405"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Inc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[INC-README.txt..windowsprogram filesappdata" ascii //weight: 1
        $x_1_2 = "$recycle.binprogramdataall userssophosINC.log.dll.exe" ascii //weight: 1
        $x_1_3 = "while deleting shadow copies from" ascii //weight: 1
        $x_1_4 = "Successfully deleted shadow copies from @d" ascii //weight: 1
        $x_1_5 = "Successfully killed processes by mask" ascii //weight: 1
        $x_1_6 = "while encrypting file" ascii //weight: 1
        $x_1_7 = "EncryptionAlgoSALSA20AESEncryptionHeader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

