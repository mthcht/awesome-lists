rule Trojan_Win32_MetshLoader_C_2147743424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MetshLoader.C!MSR"
        threat_id = "2147743424"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MetshLoader"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShamilMutex" ascii //weight: 1
        $x_1_2 = "msvc_helloworld.dll" ascii //weight: 1
        $x_1_3 = "C:\\Users\\admin\\source\\repos\\Shamil\\Release\\Shamil.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

