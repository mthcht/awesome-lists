rule Trojan_Win32_Hawkeye_PA_2147745015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hawkeye.PA!MTB"
        threat_id = "2147745015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PasswordStealer" ascii //weight: 1
        $x_1_2 = "KeyStrokeLogger" ascii //weight: 1
        $x_1_3 = "AntiVirusKiller" ascii //weight: 1
        $x_1_4 = "HawkEye Reborn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hawkeye_A_2147750440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hawkeye.A!!Hawkeye.A.gen!MTB"
        threat_id = "2147750440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hawkeye"
        severity = "Critical"
        info = "Hawkeye: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HawkEye_Keylogger_Keylog_Records_" ascii //weight: 1
        $x_1_2 = "screens\\screenshot" ascii //weight: 1
        $x_1_3 = "SELECT * FROM AntivirusProduct" ascii //weight: 1
        $x_1_4 = "WebBrowserPassView" ascii //weight: 1
        $x_1_5 = "\\pidloc.txt" ascii //weight: 1
        $x_1_6 = "\\pid.txt" ascii //weight: 1
        $x_1_7 = "holdermail.txt" ascii //weight: 1
        $x_1_8 = "wallet.dat" ascii //weight: 1
        $x_1_9 = "Keylog Records" ascii //weight: 1
        $x_1_10 = "HawkEyeKeylogger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

