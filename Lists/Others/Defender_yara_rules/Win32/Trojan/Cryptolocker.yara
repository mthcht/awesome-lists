rule Trojan_Win32_Cryptolocker_PAM_2147816727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptolocker.PAM!MTB"
        threat_id = "2147816727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Nominatus_ToxicBattery.pdb" ascii //weight: 2
        $x_2_2 = "net stop NetBackup BMR MTFTP Service /y" wide //weight: 2
        $x_2_3 = "sc config SQLTELEMETRY$ECWDB2 start= disabled" wide //weight: 2
        $x_2_4 = "vssadmin delete shadows /all /quiet && wmic shadowcopy delete && net users " ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

