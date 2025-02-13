rule Ransom_Win32_CyberVolk_PA_2147914932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CyberVolk.PA!MTB"
        threat_id = "2147914932"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CyberVolk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cvenc" wide //weight: 1
        $x_1_2 = "CyberVolk_ReadMe.txt" wide //weight: 1
        $x_3_3 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 [0-21] 20 72 61 6e 73 6f 6d 77 61 72 65}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_CyberVolk_YAA_2147915103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CyberVolk.YAA!MTB"
        threat_id = "2147915103"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CyberVolk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XPolarized\\ransom\\ransom\\Crypto\\RSA" ascii //weight: 1
        $x_1_2 = "files have been encrypted" ascii //weight: 1
        $x_1_3 = "Start Decryption" wide //weight: 1
        $x_1_4 = "CyberVolk_ReadMe.txt" wide //weight: 1
        $x_1_5 = "Cyb3r Bytes Ransomware" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_CyberVolk_PAA_2147925168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CyberVolk.PAA!MTB"
        threat_id = "2147925168"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CyberVolk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "CyberVolk ransomware" ascii //weight: 5
        $x_1_2 = "CyberVolk_ReadMe.txt" ascii //weight: 1
        $x_1_3 = "your files have been encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

