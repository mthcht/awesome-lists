rule Trojan_Win64_DelShad_SK_2147940300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DelShad.SK!MTB"
        threat_id = "2147940300"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DelShad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_2 = "ProgramData\\sessionuserhost.exe /sc onlogon /rl HIGHEST" ascii //weight: 1
        $x_1_3 = "SPG\\source\\repos\\loader\\x64\\Release\\sessionuserhost.pdb" ascii //weight: 1
        $x_1_4 = "sessionuserhost.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

