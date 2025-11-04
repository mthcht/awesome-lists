rule Ransom_Win64_WannaCrypt_PF_2147909570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/WannaCrypt.PF!MTB"
        threat_id = "2147909570"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "WannaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "limiteci/WannaCry/raw/main/WannaCry.EXE" ascii //weight: 1
        $x_1_2 = "cmd /c image.png" ascii //weight: 1
        $x_1_3 = "Keylogger" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_WannaCrypt_PAGV_2147956638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/WannaCrypt.PAGV!MTB"
        threat_id = "2147956638"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "WannaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 8b c9 c1 e1 09 f7 d1 44 0f af c1 41 8b c9 d1 e9 f7 d1 41 8b d0 c1 ea 0b 0b ca 41 33 c8 45 0f b6 42 ff 45 84 c0 75}  //weight: 2, accuracy: High
        $x_1_2 = {8b ca c1 e9 0b 33 ca 69 c9 01 80 00 00 3b ce 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

