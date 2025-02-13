rule TrojanDownloader_Win32_Darmapo_2147630352_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Darmapo"
        threat_id = "2147630352"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Darmapo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "62"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sc STOP gbpkm" ascii //weight: 1
        $x_1_2 = "sc DELETE gbpkm" ascii //weight: 1
        $x_1_3 = "sc DELETE snmgrsvc" ascii //weight: 1
        $x_1_4 = "sc DELETE snsid" ascii //weight: 1
        $x_1_5 = "sc DELETE snsms" ascii //weight: 1
        $x_10_6 = "\\msman.exe -runserivce" wide //weight: 10
        $x_10_7 = "\\drivers\\highconf.sys" wide //weight: 10
        $x_10_8 = "\\CurrentVersion\\FontSubstitutes" wide //weight: 10
        $x_10_9 = "SetLayeredWindowAttributes" wide //weight: 10
        $x_10_10 = "InternetOpenUrlW" ascii //weight: 10
        $x_10_11 = "CreateServiceW" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

