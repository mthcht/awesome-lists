rule Backdoor_Win32_Boulet_G_2147747814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Boulet.G!MTB"
        threat_id = "2147747814"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Boulet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b c6 f7 f1 46 8a 92 ?? ?? ?? ?? 30 96 ?? ?? ?? ?? 81 fe ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

