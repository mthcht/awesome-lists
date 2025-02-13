rule Ransom_Win32_Lynx_B_2147926076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lynx.B"
        threat_id = "2147926076"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lynx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[*] Starting full encryption in 5s" wide //weight: 1
        $x_1_2 = "\\background-image.jpg" wide //weight: 1
        $x_1_3 = "TOR Network: http://lynx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

