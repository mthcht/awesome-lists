rule Backdoor_Win64_Coroxy_A_2147816246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Coroxy.A"
        threat_id = "2147816246"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Coroxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe c3 8a 94 2b ?? ?? ff ff 02 c2 8a 8c 28 ?? ?? ff ff 88 8c 2b ?? ?? ff ff 88 94 28 ?? ?? ff ff 02 ca 8a 8c 29 ?? ?? ff ff 30 0e 48 ff c6 48 ff cf 75 cd}  //weight: 5, accuracy: Low
        $x_1_2 = "/tor/rendezvous2/%s" ascii //weight: 1
        $x_1_3 = "BEGIN RSA PUBLIC KEY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Coroxy_ZB_2147897699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Coroxy.ZB!MTB"
        threat_id = "2147897699"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac 48 39 7d ?? 77 ?? 48 83 7d ?? ?? 74 ?? 48 8b 55 ?? 88 02 8a 07 30 02 48 ff 45 ?? eb ?? 30 07 48 ff c9 48 83 7d ?? ?? 75 ?? 48 83 7d ?? ?? 75 ?? 66 83 7f}  //weight: 1, accuracy: Low
        $x_1_2 = "-WindowStyle Hidden -ep bypass -file" ascii //weight: 1
        $x_1_3 = "rundll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Coroxy_ZD_2147897735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Coroxy.ZD!MTB"
        threat_id = "2147897735"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2b d8 8b 45 ?? 31 18 83 45 ?? ?? 83 45 ?? ?? 8b 45 ?? 3b 45 ?? 72 50 00 8b 45 ?? 8b 55 ?? 01 02 6a 00 e8 ?? ?? ?? ?? 8b 5d ?? 03 5d ?? 03 5d ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

