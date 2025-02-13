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

