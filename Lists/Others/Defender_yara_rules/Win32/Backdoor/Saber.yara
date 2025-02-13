rule Backdoor_Win32_Saber_YA_2147739749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Saber.YA!MTB"
        threat_id = "2147739749"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Saber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_9_1 = {5c 52 65 6c 65 61 73 65 5c 53 61 62 65 72 [0-2] 2d 44 65 76 2e 70 64 62}  //weight: 9, accuracy: Low
        $x_1_2 = "<|>Chromepass<|>" ascii //weight: 1
        $x_1_3 = "<|>FireFoxbook<|>" ascii //weight: 1
        $x_1_4 = "<|>IEpass<|>" ascii //weight: 1
        $x_1_5 = "<|>Safaripass<|>" ascii //weight: 1
        $x_1_6 = "<|>Thunderbirdpass<|>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_9_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

