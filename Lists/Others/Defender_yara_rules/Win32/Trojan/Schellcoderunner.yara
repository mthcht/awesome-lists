rule Trojan_Win32_Schellcoderunner_RR_2147961663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Schellcoderunner.RR!MTB"
        threat_id = "2147961663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Schellcoderunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "froodlesphere.com" wide //weight: 1
        $x_1_2 = "quixlynest.com" wide //weight: 1
        $x_1_3 = "zentopiacrafts.com" wide //weight: 1
        $x_1_4 = "\\System32\\schtasks.exe /run /tn \"WindowsUpgradeWorker\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

