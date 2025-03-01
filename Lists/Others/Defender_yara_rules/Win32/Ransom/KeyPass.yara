rule Ransom_Win32_KeyPass_MK_2147785423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/KeyPass.MK!MTB"
        threat_id = "2147785423"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyPass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!!!WHY_MY_FILES_NOT_OPEN!!!.txt" ascii //weight: 1
        $x_1_2 = "important files are encrypted" ascii //weight: 1
        $x_1_3 = "Price for decryption" ascii //weight: 1
        $x_1_4 = "Your personal id:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_KeyPass_MAK_2147808981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/KeyPass.MAK!MTB"
        threat_id = "2147808981"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyPass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 b0 58 5c 63 00 8b d6 8b ce c1 ea 07 69 fa 00 00 00 1b c1 e1 19 69 d2 1b 01 00 00 33 f9 8b ce c1 e1 08 0b ce c1 e1 08 0b f9 8d 0c 36 33 d1 33 c9 33 d6 0b cf 0b d7 89 0c c5 50 8e 68 00 89 14 c5 54 8e 68 00 40 3d 00 01 00 00 7c b2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

