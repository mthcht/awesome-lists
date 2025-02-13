rule Trojan_Win32_TinyADRecon_LKV_2147897210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TinyADRecon.LKV!MTB"
        threat_id = "2147897210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TinyADRecon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Users\\rainman\\source\\repos\\ADRecon\\TinyADRecon\\obj\\Release\\TinyADRecon.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

