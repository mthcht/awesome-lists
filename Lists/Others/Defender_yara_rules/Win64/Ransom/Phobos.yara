rule Ransom_Win64_Phobos_MDZ_2147966875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Phobos.MDZ!MTB"
        threat_id = "2147966875"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Phobos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "phobosransom" ascii //weight: 2
        $x_2_2 = "reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_2_3 = "LUCKYWAREFUCKER.pdb" ascii //weight: 2
        $x_1_4 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

