rule Trojan_Win32_CredTheftBin_BB_2147966539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CredTheftBin.BB"
        threat_id = "2147966539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CredTheftBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "70"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Connecting to Outlook" wide //weight: 10
        $x_10_2 = "CredUIPromptForWindowsCredentialsW" ascii //weight: 10
        $x_10_3 = "CredUnPackAuthenticationBufferW" ascii //weight: 10
        $x_10_4 = "C:\\users\\public\\" wide //weight: 10
        $x_10_5 = ".txt" wide //weight: 10
        $x_10_6 = "Credui.dll" ascii //weight: 10
        $x_10_7 = "C:\\windows\\system32\\wtsapi32.IsInteractiveUserSession" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

