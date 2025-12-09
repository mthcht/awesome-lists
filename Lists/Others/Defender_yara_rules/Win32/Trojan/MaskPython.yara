rule Trojan_Win32_MaskPython_YD_2147959047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MaskPython.YD!MTB"
        threat_id = "2147959047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MaskPython"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "import" wide //weight: 10
        $x_10_2 = "urllib.request" wide //weight: 10
        $x_10_3 = "base64" wide //weight: 10
        $x_10_4 = ".b64decode" wide //weight: 10
        $x_10_5 = "urllib.request.urlopen" wide //weight: 10
        $x_10_6 = "http" wide //weight: 10
        $x_10_7 = "read().decode" wide //weight: 10
        $x_10_8 = "exec" wide //weight: 10
        $x_10_9 = "%localappdata%" wide //weight: 10
        $x_10_10 = ".txt" wide //weight: 10
        $n_10_11 = "python.exe" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

