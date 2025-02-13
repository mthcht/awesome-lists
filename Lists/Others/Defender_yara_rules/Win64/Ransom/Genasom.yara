rule Ransom_Win64_Genasom_AR_2147754406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Genasom.AR!MTB"
        threat_id = "2147754406"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Genasom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.encrypt" ascii //weight: 1
        $x_10_2 = "C:/Users/windows/go/src/VashRansomwarev2/Encrypt.go" ascii //weight: 10
        $x_1_3 = "decrypt all your files after paying the ransom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

