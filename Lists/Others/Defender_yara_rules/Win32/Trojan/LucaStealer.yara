rule Trojan_Win32_LucaStealer_ARA_2147976854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LucaStealer.ARA!MTB"
        threat_id = "2147976854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LucaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {eb 10 0f b6 2c 10 31 dd 31 c5 87 dd 88 1c 02 87 dd 40 39 c1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

