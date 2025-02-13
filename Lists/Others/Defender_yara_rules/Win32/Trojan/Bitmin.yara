rule Trojan_Win32_Bitmin_BM_2147838853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bitmin.BM!MTB"
        threat_id = "2147838853"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bitmin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "renimuse.ocry.com/renim64.exe" ascii //weight: 2
        $x_2_2 = "start intelusr.exe" ascii //weight: 2
        $x_2_3 = "renimuse.ocry.com/renim32.exe" ascii //weight: 2
        $x_1_4 = "ping 127.0.0.1 -n 8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bitmin_NB_2147895469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bitmin.NB!MTB"
        threat_id = "2147895469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bitmin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e8 fb ef ff ff 8b 5c 24 ?? 2b c7 3b c3 73 02 8b d8 8b 56 ?? 83 c8 ff 2b c2 3b c3 77 05}  //weight: 5, accuracy: Low
        $x_1_2 = "VC6_IN_VM_Dll_2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

