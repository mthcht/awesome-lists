rule Ransom_Win32_Legion_PA_2147752854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Legion.PA!MTB"
        threat_id = "2147752854"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Legion"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Legion__Ransomware" wide //weight: 1
        $x_1_2 = "\\READ-Me-Now.txt" wide //weight: 1
        $x_1_3 = "\\Desktop\\farshad" wide //weight: 1
        $x_1_4 = "bytesToBeEncr" ascii //weight: 1
        $x_1_5 = "encryptdir" ascii //weight: 1
        $x_1_6 = "passwordBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

