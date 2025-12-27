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

rule Trojan_Win64_DelShad_MR_2147950652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DelShad.MR!MTB"
        threat_id = "2147950652"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DelShad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {40 00 00 40 2e 72 73 72 63 00 00 00 58 f7 00 00 00 a0 44 00 00 f8 00 00 00 bc 42}  //weight: 5, accuracy: High
        $x_5_2 = {40 00 00 40 2e 69 64 61 74 61 ?? ?? ?? 10 ?? ?? ?? a0 45 00 00 02 00 00 00 b4 43}  //weight: 5, accuracy: Low
        $x_5_3 = {40 00 00 40 20 20 20 20 20 20 20 20 38 3c 41 00 00 20 03 00 00 28 41 00 00 7a 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

