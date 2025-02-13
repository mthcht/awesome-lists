rule Trojan_Win64_RustWorm_DA_2147924486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustWorm.DA!MTB"
        threat_id = "2147924486"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "pkillapt-getremove-ysystemctlmask" ascii //weight: 10
        $x_1_2 = "Disabled and removed:" ascii //weight: 1
        $x_10_3 = "rootkitsuricata" ascii //weight: 10
        $x_1_4 = "crowdstrikefalcon" ascii //weight: 1
        $x_1_5 = "wiptablesfirewall" ascii //weight: 1
        $x_1_6 = "malwarebytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

