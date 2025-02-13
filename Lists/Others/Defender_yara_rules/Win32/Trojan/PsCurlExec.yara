rule Trojan_Win32_PsCurlExec_A_2147932738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsCurlExec.A!MTB"
        threat_id = "2147932738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsCurlExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "hidden" wide //weight: 1
        $x_1_3 = "curl" wide //weight: 1
        $x_1_4 = "| iex" wide //weight: 1
        $x_1_5 = {68 00 74 00 74 00 70 00 90 00 02 00 50 00 2e 00 70 00 68 00 70 00 3f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

