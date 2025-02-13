rule Trojan_Win64_T1547_005_SecuritySupportProvider_A_2147846086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/T1547_005_SecuritySupportProvider.A"
        threat_id = "2147846086"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "T1547_005_SecuritySupportProvider"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "lsadump::packages" wide //weight: 10
        $x_10_2 = "misc::memssp" wide //weight: 10
        $x_10_3 = "misc::lock" wide //weight: 10
        $x_10_4 = "misc::printnightmare" wide //weight: 10
        $x_10_5 = "misc::spooler" wide //weight: 10
        $x_10_6 = "sekurlsa::livessp" wide //weight: 10
        $x_10_7 = "sekurlsa::ssp" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

