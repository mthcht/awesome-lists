rule Ransom_Win32_DMREncryptor_PA_2147746284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DMREncryptor.PA!MTB"
        threat_id = "2147746284"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DMREncryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\!!! READ THIS !!!.hta" ascii //weight: 1
        $x_1_2 = "TheDMR_Encrypter" ascii //weight: 1
        $x_1_3 = "All your files have been encrypted!" ascii //weight: 1
        $x_1_4 = "background.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

