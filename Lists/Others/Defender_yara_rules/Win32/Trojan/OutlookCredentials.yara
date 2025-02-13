rule Trojan_Win32_OutlookCredentials_A_2147808083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OutlookCredentials.A"
        threat_id = "2147808083"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OutlookCredentials"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "adb.dll" wide //weight: 10
        $x_10_2 = "Control_RunDLL" wide //weight: 10
        $x_10_3 = "password" wide //weight: 10
        $x_10_4 = "Microsoft.Office.Interop.Outlook" wide //weight: 10
        $x_10_5 = "outlook.application" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

