rule Trojan_MSIL_SelfDelf_EM_2147900455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SelfDelf.EM!MTB"
        threat_id = "2147900455"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SelfDelf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FQAWRDHCWRTMVI" wide //weight: 1
        $x_1_2 = "SELECT * FROM Win32_VideoController" wide //weight: 1
        $x_1_3 = "ShowSuperHidden" wide //weight: 1
        $x_1_4 = "DisableTaskMgr" wide //weight: 1
        $x_1_5 = "SELECT * FROM Win32_PhysicalMemory" wide //weight: 1
        $x_1_6 = "Trinity" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

