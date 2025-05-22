rule Ransom_Win64_ViceSociety_SM_2147942016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/ViceSociety.SM!MTB"
        threat_id = "2147942016"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "ViceSociety"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If you get this message, your network was hacked!" wide //weight: 1
        $x_1_2 = "sensitive data and then encrypted all the data" wide //weight: 1
        $x_1_3 = "Contact us for price and get decryption" wide //weight: 1
        $x_1_4 = "start DDOS attack on you website and infrastructures." wide //weight: 1
        $x_1_5 = "vssadmin.exe Delete Shado" wide //weight: 1
        $x_1_6 = "del Default.rdp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

