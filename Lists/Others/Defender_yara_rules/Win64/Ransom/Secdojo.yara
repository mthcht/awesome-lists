rule Ransom_Win64_Secdojo_YAB_2147911276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Secdojo.YAB!MTB"
        threat_id = "2147911276"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Secdojo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 44 24 20 48 8b 4c 24 50 0f b6 04 01 48 63 4c 24 20 48 8b 54 24 48 0f b6 0c 0a 33 c1 48 63 4c 24 20 48 8b 54 24 58 88 04 0a}  //weight: 1, accuracy: High
        $x_1_2 = "bcdedit /set {default} recoveryenabled no" wide //weight: 1
        $x_1_3 = "cmd.exe /c wbadmin delete catalog -quiet" wide //weight: 1
        $x_1_4 = "cmd.exe /c vssadmin delete shadows /all /quiet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

