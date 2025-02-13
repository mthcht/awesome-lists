rule TrojanDownloader_Win32_Stantinko_A_2147735536_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Stantinko.A!MTB"
        threat_id = "2147735536"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Stantinko"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "USB0_Init" ascii //weight: 1
        $x_1_2 = "CHECKMATE" ascii //weight: 1
        $x_1_3 = "2004.DLL" ascii //weight: 1
        $x_1_4 = "2edklrel.3ln" wide //weight: 1
        $x_1_5 = ":\\Theme Engine Service\\Release\\44,90" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

