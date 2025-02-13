rule Trojan_Win64_XDRKiller_DA_2147932563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XDRKiller.DA!MTB"
        threat_id = "2147932563"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XDRKiller"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "rust_xdr_fucker.pdb" ascii //weight: 10
        $x_1_2 = "ZwSuspendProcess" ascii //weight: 1
        $x_1_3 = "360Safe.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

