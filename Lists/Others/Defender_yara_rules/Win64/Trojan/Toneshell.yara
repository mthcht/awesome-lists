rule Trojan_Win64_Toneshell_GV_2147981299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Toneshell.GV!MTB"
        threat_id = "2147981299"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Toneshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 d1 88 ca 8b 8d ?? ?? ?? ?? 88 14 08 8b 85 ?? ?? ?? ?? 83 c0 01 89 85 ?? ?? ?? ?? 83 bd [0-5] 0f 83 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 0f be 0c 08 8b 95}  //weight: 1, accuracy: Low
        $x_1_2 = "schtasks /create /sc minute /mo 2 /tn " ascii //weight: 1
        $x_1_3 = "DefWindowProcW1222_test" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

