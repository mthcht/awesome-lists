rule Trojan_Win64_Quasarrat_RR_2147959834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Quasarrat.RR!MTB"
        threat_id = "2147959834"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Quasarrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ChainingModeCBC" wide //weight: 1
        $x_1_2 = "ChainingMode" wide //weight: 1
        $x_1_3 = "AWAVAUATVWUSH" ascii //weight: 1
        $x_1_4 = "UAWAVAUATVWSPH" ascii //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "VirtualProtect" ascii //weight: 1
        $x_1_7 = "CreateThread" ascii //weight: 1
        $x_1_8 = "bcrypt.dll" ascii //weight: 1
        $x_1_9 = "BCryptDestroyKey" ascii //weight: 1
        $x_1_10 = "WaitForSingleObject" ascii //weight: 1
        $x_5_11 = {48 83 c4 20 c7 06 00 00 00 00 48 83 ec 20 4c 89 f9 4c 89 ea 41 b8 20 00 00 00 49 89 f1 41 ff d4 48 83 c4 20 85 c0 0f 84}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

