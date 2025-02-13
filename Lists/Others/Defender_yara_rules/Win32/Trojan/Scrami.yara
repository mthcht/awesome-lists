rule Trojan_Win32_Scrami_CB_2147839145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scrami.CB!MTB"
        threat_id = "2147839145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scrami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "prok.exe" ascii //weight: 1
        $x_1_2 = "ProcessStartInfo" ascii //weight: 1
        $x_1_3 = "ProcessWindowStyle" ascii //weight: 1
        $x_1_4 = "powershell.exe" ascii //weight: 1
        $x_1_5 = "0ASQBuAHYAbwBrAGU" wide //weight: 1
        $x_1_6 = "ACAALQBVAHIAaQA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

