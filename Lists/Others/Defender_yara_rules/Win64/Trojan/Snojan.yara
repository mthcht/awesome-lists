rule Trojan_Win64_Snojan_KD_2147833638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Snojan.KD!MTB"
        threat_id = "2147833638"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Snojan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 54 24 08 48 89 54 24 18 33 d2 48 8b c1 48 8b 4c 24 18 48 f7 f1 48 8b c2 48 8b 4c 24 40 0f be 04 01 8b 4c 24 04 33 c8 8b c1 48 63 0c 24 48 8b 54 24 30 88 04 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Snojan_MA_2147847068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Snojan.MA!MTB"
        threat_id = "2147847068"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Snojan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Nsu2OdiwodOs2" ascii //weight: 5
        $x_5_2 = {4e 73 75 32 4f 64 69 77 6f 64 4f 73 32 00 00 00 0d 0a 0d 0a 00 00 00 00 50 4f 53 54 20 00 00 00 20 48 54 54 50 2f 31}  //weight: 5, accuracy: High
        $x_2_3 = "SE_ASSIGNPRIMARYTOKEN_NAME %d" ascii //weight: 2
        $x_2_4 = "Can't OpenProcessToken err %d PID %d handle %p" ascii //weight: 2
        $x_2_5 = "/c del" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

