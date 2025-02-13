rule HackTool_Linux_Meltdown_A_2147927963_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Meltdown.A"
        threat_id = "2147927963"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Meltdown"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sudo sh -c \"echo 0  > /proc/sys/kernel/kptr_restric" ascii //weight: 1
        $x_1_2 = "Checking whether system is affected by Variant 3: rogue data cache load (CVE-2017-5754), a.k.a MELTDOWN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

