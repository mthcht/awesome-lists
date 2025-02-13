rule Ransom_Win64_NetWalker_AD_2147766216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/NetWalker.AD!MTB"
        threat_id = "2147766216"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "NetWalker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "runas" wide //weight: 1
        $x_1_2 = "changepk.exe" wide //weight: 1
        $x_1_3 = "Launcher.SystemSettings" wide //weight: 1
        $x_1_4 = "start" wide //weight: 1
        $x_1_5 = "mscfile" wide //weight: 1
        $x_1_6 = "exefile" wide //weight: 1
        $x_1_7 = "kill" ascii //weight: 1
        $x_1_8 = "unlock" ascii //weight: 1
        $x_1_9 = "white" ascii //weight: 1
        $x_1_10 = "svcwait" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

