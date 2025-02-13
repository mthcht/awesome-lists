rule Ransom_Win32_FileEncoder_A_2147756883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileEncoder.A!MTB"
        threat_id = "2147756883"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileEncoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.encryptFile" ascii //weight: 1
        $x_1_2 = "main.makeBatFile" ascii //weight: 1
        $x_1_3 = "main.deleteShadowCopy" ascii //weight: 1
        $x_1_4 = "main.reboot" ascii //weight: 1
        $x_1_5 = "main.randomBatFileName" ascii //weight: 1
        $x_1_6 = "crypto/rsa.encrypt" ascii //weight: 1
        $x_1_7 = "main.(*myService).Execute" ascii //weight: 1
        $x_1_8 = "Go build ID:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileEncoder_A_2147756883_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileEncoder.A!MTB"
        threat_id = "2147756883"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileEncoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 fa 10 75 02 33 d2 ac 32 82 ?? ?? ?? ?? aa 42 49 75 ed}  //weight: 2, accuracy: Low
        $x_1_2 = {bb 01 00 00 00 d3 e3 23 d8 74 2d 80 c1 41 88 0d ?? ?? ?? ?? 80 e9 41 c7 05 ?? ?? ?? ?? 3a 5c 2a 2e c6 05 ?? ?? ?? ?? 2a c6 05 ?? ?? ?? ?? 00 50 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

