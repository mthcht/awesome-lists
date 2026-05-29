rule Backdoor_Win64_InfoStealer_AAA_2147970531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/InfoStealer.AAA!AMTB"
        threat_id = "2147970531"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "F:\\proramming\\Hack\\STEALERS\\LOADERS\\Loader\\x64\\Release\\Loader.pdb" ascii //weight: 10
        $x_2_2 = "https://raw.githubusercontent.com/commit666/test/refs/heads/main/ProxyScrapper2023.exe" ascii //weight: 2
        $x_2_3 = "\\%d.tmp" ascii //weight: 2
        $x_2_4 = "URLDownloadToFileA" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

