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

rule Ransom_Win32_Lynx_MKV_2147935392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lynx.MKV!MTB"
        threat_id = "2147935392"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lynx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe c2 88 94 31 b0 00 00 00 8b 54 24 10 33 c9 8b 74 24 20 8a 84 0c ?? ?? ?? ?? 41 30 04 37 47 8b 74 24 1c 3b fa 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

