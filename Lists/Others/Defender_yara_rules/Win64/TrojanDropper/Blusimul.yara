rule TrojanDropper_Win64_Blusimul_ARA_2147889127_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Blusimul.ARA!MTB"
        threat_id = "2147889127"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Blusimul"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BluescreenSimulator\\obj\\Release\\BluescreenSimulator.pdb" ascii //weight: 2
        $x_2_2 = "shutdown to prevent damage to your computer." ascii //weight: 2
        $x_2_3 = "A program to simulate BSODs with lots of features." ascii //weight: 2
        $x_2_4 = "IsDumpComplete" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win64_Blusimul_SGA_2147891291_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Blusimul.SGA!MTB"
        threat_id = "2147891291"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Blusimul"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CheckTokenMembership" ascii //weight: 1
        $x_1_2 = "HeapSetInformation" ascii //weight: 1
        $x_1_3 = "DecryptFileA" ascii //weight: 1
        $x_1_4 = "wextract.pdb" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_6 = "wextract_cleanup%d" ascii //weight: 1
        $x_1_7 = "DoInfInstall" ascii //weight: 1
        $x_1_8 = "BluescreenSimulator.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

