rule Trojan_Win32_MSILInject_GX_2147909040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MSILInject.GX!MTB"
        threat_id = "2147909040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MSILInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 1
        $x_1_2 = "d17b41c9-3955-4890-95b8-887aac006e0b" ascii //weight: 1
        $x_1_3 = "_.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

