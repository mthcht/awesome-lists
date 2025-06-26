rule Ransom_MSIL_CyberLock_GVA_2147944681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CyberLock.GVA!MTB"
        threat_id = "2147944681"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CyberLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".cyberlock" ascii //weight: 1
        $x_1_2 = "All your files have been encrypted." ascii //weight: 1
        $x_1_3 = "How do I pay?" ascii //weight: 1
        $x_1_4 = "You must send $ 25000 (USD) to the first Monero address" ascii //weight: 1
        $x_1_5 = "We are CyberLock - Anonymous." ascii //weight: 1
        $x_1_6 = "ReadMeNow.txt" ascii //weight: 1
        $x_1_7 = "HKCU:\\Control Panel\\Desktop" ascii //weight: 1
        $x_1_8 = "Start-Process cipher.exe -ArgumentList \"/w:$env:USERPROFILE\" -WindowStyle Hidden" ascii //weight: 1
        $x_5_9 = "Email: cyberspectreislocked@onionmail.org" ascii //weight: 5
        $x_1_10 = "Please send a screenshot of the payment. We will respond within 5 hours with the decryption key." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

