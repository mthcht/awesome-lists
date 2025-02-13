rule TrojanDownloader_Win32_Bloon_A_2147593717_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bloon.gen!A"
        threat_id = "2147593717"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bloon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Your virus protection status is bad" ascii //weight: 10
        $x_10_2 = "Spyware Activity Detected" ascii //weight: 10
        $x_1_3 = "\\balloon.wav" ascii //weight: 1
        $x_1_4 = "BINARY" ascii //weight: 1
        $x_1_5 = "Shell_TrayWnd" ascii //weight: 1
        $x_1_6 = "TrayNotifyWnd" ascii //weight: 1
        $x_1_7 = "spyware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bloon_B_2147593718_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bloon.gen!B"
        threat_id = "2147593718"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bloon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "211"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "AutoRun.cpp:AddApplicationToRegistryRun: RegCreateKeyEx failed" ascii //weight: 100
        $x_100_2 = "ec1b922d-838d-44a1-a2ef-e92d4358f49a" ascii //weight: 100
        $x_10_3 = "www.nigerov.net" ascii //weight: 10
        $x_10_4 = "SearchMaid TrayICON" ascii //weight: 10
        $x_1_5 = "Attention! Failure to delete spyware from your PC can reslut in damage" ascii //weight: 1
        $x_1_6 = "spyware from your operating system." ascii //weight: 1
        $x_1_7 = "Click \"OK\" to get all available Anti Spyware software." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

