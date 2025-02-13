rule Trojan_Win32_MSILInjector_GZ_2147906437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MSILInjector.GZ!MTB"
        threat_id = "2147906437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MSILInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 1
        $x_1_2 = "mscoree.dll" ascii //weight: 1
        $x_1_3 = "Kknifers Reintegrations" ascii //weight: 1
        $x_1_4 = "_.pdb" ascii //weight: 1
        $x_1_5 = "d17b41c9-3955-4890-95b8-887aac006e0b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

