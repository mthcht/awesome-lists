rule Trojan_Win64_FoxChair_A_2147960859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FoxChair.A!dha"
        threat_id = "2147960859"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FoxChair"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "found ESXi%d.%d build-%d" ascii //weight: 1
        $x_1_2 = "vmkernel base: %p,qpBrokerList: %p" ascii //weight: 1
        $x_1_3 = "vmx base is: %p" ascii //weight: 1
        $x_1_4 = "maxDomain: %08x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_FoxChair_B_2147960860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FoxChair.B!dha"
        threat_id = "2147960860"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FoxChair"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "devcon.exe" ascii //weight: 1
        $x_1_2 = "kdu.exe" ascii //weight: 1
        $x_1_3 = "VMWVMCIHOSTDEV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

