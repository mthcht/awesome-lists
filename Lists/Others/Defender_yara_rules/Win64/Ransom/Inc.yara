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

rule Ransom_Win64_Inc_AIN_2147974341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Inc.AIN!MTB"
        threat_id = "2147974341"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Inc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 89 cf 48 8d 15 a3 78 1b 00 48 8d 8c 24 80 03 00 00 41 b8 03 ?? ?? ?? ?? ?? ?? ?? ?? 48 8d 15 8c 78 1b 00 48 8d 8c 24 40 01 00 00 41 b8 0e ?? ?? ?? ?? ?? ?? ?? ?? 4c 8d 05 80 78 1b 00 48 8d 8c 24 08 06 00 00 48 8d 94 24 40 01 00 00 41 b9 03 ?? ?? ?? ?? ?? ?? ?? ?? 4c 8d 05 61 78 1b 00 48 8d 8c 24 40 01 00 00 48 8d 94 24 08 06 00 00 41 b9 2c}  //weight: 2, accuracy: Low
        $x_1_2 = {48 8d 8c 24 40 01 00 00 48 8d 94 24 80 03 00 00 4c 8d 84 24 f0 06 ?? ?? ?? ?? ?? ?? ?? 48 8d 15 a0 76 1b 00 48 8d 8c 24 80 03 00 00 41 b8 04 ?? ?? ?? ?? ?? ?? ?? ?? 4c 8d 05 86 76 1b 00 48 8d 8c 24 08 06 00 00 48 8d 94 24 80 03 00 00 41 b9 04 ?? ?? ?? ?? ?? ?? ?? ?? 4c 8d 05 68 76 1b 00 48 8d 8c 24 80 03 00 00 48 8d 94 24 08 06 00 00 41 b9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

