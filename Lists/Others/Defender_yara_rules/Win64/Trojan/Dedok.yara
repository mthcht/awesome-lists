rule Trojan_Win64_Dedok_MA_2147918657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dedok.MA!MTB"
        threat_id = "2147918657"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dedok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 6
        $x_1_2 = "whoami" ascii //weight: 1
        $x_1_3 = "ipconfig" ascii //weight: 1
        $x_1_4 = "Get-WmiObject -Class Win32_UserAccount" ascii //weight: 1
        $x_1_5 = "Get-Process" ascii //weight: 1
        $x_1_6 = "Get-Service" ascii //weight: 1
        $x_1_7 = "Get-ChildItem Env" ascii //weight: 1
        $x_1_8 = "Get-PSDrive" ascii //weight: 1
        $x_1_9 = {54 65 6d 70 [0-15] 2e 6c 6f 67}  //weight: 1, accuracy: Low
        $x_1_10 = "screenshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

