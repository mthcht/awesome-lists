rule Trojan_Win32_DarkTrack_PA_2147755576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkTrack.PA!MTB"
        threat_id = "2147755576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkTrack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "080IAM010010DAR8K89TR3SDTACK" ascii //weight: 5
        $x_1_2 = "Local Victim" ascii //weight: 1
        $x_1_3 = "AntiVirusProduct" ascii //weight: 1
        $x_1_4 = "\\Yandex\\YandexBrowser\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_5 = "\\Comodo\\Dragon\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_6 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_7 = "\\Skype\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

